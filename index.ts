// GuardianX Engine — HTTP API server + socket.io relay on a single port.
//
// This service runs on Railway and handles all heavy compute that Vercel
// serverless can't (due to 10-60s timeouts + no Python/bun runtime):
//   POST /api/run-sast      — SAST vulnerability scan pipeline (~95s)
//   POST /api/run-dast      — DAST VAPT engagement (~95s)
//   POST /api/run-exploit   — Run exploit PoC vs original/patched code (~10s)
//   POST /api/generate-pdf  — Generate VAPT report PDF (~30s)
//   POST /api/run-scraper   — Run Python audit scraper (~60s)
//   GET  /healthz           — Health check
//
// socket.io relay runs on the SAME httpServer (path: /socket.io) so browsers
// get real-time pipeline events. The in-process broadcaster emits directly
// to the io instance (no socket.io-client network hop).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Server } from "socket.io";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runScan } from "./src/lib/sentinel/engine/pipeline";
import { runEngagement } from "./src/lib/sentinel/engine/redagent-pipeline";
import { runExploit, runSandbox } from "./src/lib/sentinel/engine/sandbox";
import { db } from "./src/lib/db";

const PORT = parseInt(process.env.PORT || "3003", 10);
const ENGINE_INTERNAL_KEY = process.env.ENGINE_INTERNAL_KEY || "";

// ── Generate z-ai config file on startup ──────────────────────────────────
// The z-ai SDK reads /etc/.z-ai-config or ~/.z-ai-config. On Railway, the
// start.sh script may not run (Railway uses `bun index.ts` directly), so we
// generate the config file here in the entry point.
async function ensureZaiConfig() {
  const fs = await import("node:fs/promises");
  const os = await import("node:os");
  const path = await import("node:path");

  const configPaths = [
    "/etc/.z-ai-config",
    path.join(os.homedir(), ".z-ai-config"),
    ".z-ai-config",
  ];

  // Check if any config already exists
  for (const p of configPaths) {
    try {
      await fs.access(p);
      console.log(`[z-ai] config found at ${p}`);
      return;
    } catch {
      // doesn't exist, continue
    }
  }

  // Generate from ZAI_CONFIG env var
  if (process.env.ZAI_CONFIG) {
    const config = process.env.ZAI_CONFIG;
    for (const p of configPaths) {
      try {
        await fs.writeFile(p, config, "utf-8");
        console.log(`[z-ai] wrote config to ${p} from ZAI_CONFIG env var`);
        return;
      } catch {
        // might not have permission (e.g. /etc/), try next
      }
    }
  }

  // Generate from individual env vars
  if (process.env.ZAI_API_KEY) {
    const config = JSON.stringify({
      baseUrl: process.env.ZAI_BASE_URL || "https://internal-api.z.ai/v1",
      apiKey: process.env.ZAI_API_KEY,
    });
    for (const p of configPaths) {
      try {
        await fs.writeFile(p, config, "utf-8");
        console.log(`[z-ai] wrote config to ${p} from ZAI_API_KEY env var`);
        return;
      } catch {
        // try next
      }
    }
  }

  console.warn("[z-ai] WARNING: No config found and ZAI_CONFIG/ZAI_API_KEY not set — AI features will fail");
}

// Run config generation before starting the server
await ensureZaiConfig();

// ── HTTP server ─────────────────────────────────────────────────────────────
const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url || "/", `http://localhost:${PORT}`);
  const path = url.pathname;
  const method = req.method || "GET";

  // CORS headers (browsers connect directly for socket.io; HTTP is called server-to-server)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Engine-Key");
  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── Health check (no auth) ────────────────────────────────────────────────
  if (path === "/healthz" && method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      ok: true,
      service: "guardianx-engine",
      uptime: process.uptime(),
      sockets: io.engine.clientsCount,
    }));
    return;
  }

  // ── Auth check for /api/* endpoints ───────────────────────────────────────
  if (path.startsWith("/api/")) {
    if (ENGINE_INTERNAL_KEY && req.headers["x-engine-key"] !== ENGINE_INTERNAL_KEY) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized — invalid X-Engine-Key" }));
      return;
    }
  }

  // ── Read request body ─────────────────────────────────────────────────────
  const body = await new Promise<string>((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
  const json = body ? JSON.parse(body) : {};

  try {
    // ── POST /api/run-sast ────────────────────────────────────────────────
    if (path === "/api/run-sast" && method === "POST") {
      const { codebaseId, scanId } = json;
      if (!codebaseId || !scanId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "codebaseId and scanId required" }));
        return;
      }
      // Fire-and-forget: return 202 immediately, run pipeline in background
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, scanId, status: "started" }));

      // Run the pipeline — events are emitted via the in-process broadcaster
      setImmediate(() => {
        runScan(codebaseId, scanId, (e) => {
          // Emit to the scan's room + global room
          io.to(`scan:${e.scanId}`).emit("pipeline:event", e);
          io.to("global").emit("pipeline:event", e);
          return Promise.resolve();
        }).catch((err) => {
          console.error("[run-sast] pipeline crashed:", err);
          io.to(`scan:${scanId}`).emit("pipeline:event", {
            scanId,
            stage: "failed",
            message: `Pipeline crashed: ${err?.message ?? err}`,
            level: "error",
            ts: new Date().toISOString(),
          });
        });
      });
      return;
    }

    // ── POST /api/run-dast ────────────────────────────────────────────────
    if (path === "/api/run-dast" && method === "POST") {
      const { targetId, engagementId } = json;
      if (!targetId || !engagementId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "targetId and engagementId required" }));
        return;
      }
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, engagementId, status: "started" }));

      setImmediate(() => {
        runEngagement(targetId, engagementId, (e) => {
          io.to(`engagement:${e.engagementId}`).emit("redagent:event", e);
          io.to("global").emit("redagent:event", e);
          return Promise.resolve();
        }).catch((err) => {
          console.error("[run-dast] pipeline crashed:", err);
          io.to(`engagement:${engagementId}`).emit("redagent:event", {
            engagementId,
            stage: "failed",
            message: `Pipeline crashed: ${err?.message ?? err}`,
            level: "error",
            ts: new Date().toISOString(),
          });
        });
      });
      return;
    }

    // ── POST /api/run-exploit ─────────────────────────────────────────────
    if (path === "/api/run-exploit" && method === "POST") {
      const { patchId, target } = json;
      if (!patchId || !target) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "patchId and target required" }));
        return;
      }

      // Look up the patch
      const patch = await db.patch.findFirst({
        where: { OR: [{ patchId }, { id: patchId }] },
      });
      if (!patch) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Patch not found" }));
        return;
      }

      const isPatched = target === "patched";
      const targetCode = isPatched ? (patch.patchedCode as string) : (patch.originalCode as string);
      const exploitCode = (patch.exploitCode as string) || "";
      const filename = (patch.affectedFile as string) || "target.js";

      const result = await runExploit(exploitCode, targetCode, filename, {
        label: isPatched ? "patched" : "original",
      });

      // Persist the result
      if (isPatched) {
        await db.patch.update({
          where: { id: patch.id as string },
          data: { exploitPatchedResult: JSON.stringify(result) },
        });
      } else {
        await db.patch.update({
          where: { id: patch.id as string },
          data: { exploitOriginalResult: JSON.stringify(result) },
        });
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
      return;
    }

    // ── POST /api/run-sandbox-test (auto-remediation-enhance) ────────────
    // Runs an arbitrary testCode against a targetCode (patched or original)
    // in the bun sandbox. Used by /api/patches/[id]/test to run the
    // auto-generated regression test.
    if (path === "/api/run-sandbox-test" && method === "POST") {
      const { testCode, patchedCode, targetFilename } = json;
      if (!testCode || !patchedCode) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "testCode and patchedCode required" }));
        return;
      }
      const result = await runSandbox(testCode, {
        patchedCode,
        patchedFilename: targetFilename || "target.js",
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        exit_code: result.exitCode,
        passed: result.passed,
        stdout: result.stdout,
        stderr: result.stderr,
        logs: result.logs,
        duration_ms: result.durationMs,
        timed_out: result.timedOut,
      }));
      return;
    }

    // ── POST /api/generate-pdf ───────────────────────────────────────────
    if (path === "/api/generate-pdf" && method === "POST") {
      const { engagementId } = json;
      if (!engagementId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "engagementId required" }));
        return;
      }

      // Fetch engagement + target + findings from Supabase
      const engagement = await db.engagement.findUnique({
        where: { id: engagementId },
        include: { target: true, findings: true },
      });
      if (!engagement) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Engagement not found" }));
        return;
      }

      const dir = await mkdtemp(join(tmpdir(), "guardianx-pdf-"));
      try {
        const jsonPath = join(dir, "engagement.json");
        const pdfPath = join(dir, "engagement.pdf");
        const scriptPath = join(process.cwd(), "scripts", "generate-vapt-report.py");

        // Serialize engagement data for the Python script
        const payload = {
          id: engagement.id,
          status: engagement.status,
          startedAt: engagement.startedAt,
          completedAt: engagement.completedAt,
          crawlSummary: engagement.crawlSummary,
          target: engagement.target,
          findings: engagement.findings,
        };
        await writeFile(jsonPath, JSON.stringify(payload, null, 2), "utf8");

        // Spawn python3 to generate the PDF
        const exitCode = await new Promise<number>((resolve) => {
          const child = spawn("python3", [scriptPath, jsonPath, pdfPath], {
            cwd: dir,
            env: { ...process.env, PYTHONUNBUFFERED: "1" },
          });
          let stderr = "";
          child.stderr.on("data", (d) => (stderr += d.toString()));
          child.on("close", (code) => {
            if (code !== 0) console.error("[generate-pdf] python stderr:", stderr);
            resolve(code ?? 1);
          });
        });

        if (exitCode !== 0) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "PDF generation failed" }));
          return;
        }

        const pdfBuffer = await readFile(pdfPath);
        res.writeHead(200, {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="guardianx-vapt-${engagementId}.pdf"`,
          "Content-Length": pdfBuffer.length.toString(),
          "Cache-Control": "no-store",
        });
        res.end(pdfBuffer);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
      return;
    }

    // ── POST /api/run-scraper ────────────────────────────────────────────
    if (path === "/api/run-scraper" && method === "POST") {
      // Ensure audit_id is present (scraper requires it as a UUID)
      const config = { ...json };
      if (!config.audit_id) {
        config.audit_id = randomUUID();
      }

      const dir = await mkdtemp(join(tmpdir(), "guardianx-scraper-"));
      try {
        const configPath = join(dir, "config.json");
        const scriptPath = join(process.cwd(), "audit-scraper", "run.py");

        await writeFile(configPath, JSON.stringify(config, null, 2), "utf8");

        // The scraper reads config from argv[1] and writes JSON result to stdout.
        // We capture stdout and return it as the response.
        const { exitCode, stdout, stderr } = await new Promise<{
          exitCode: number;
          stdout: string;
          stderr: string;
        }>((resolve) => {
          const child = spawn("python3", [scriptPath, configPath], {
            cwd: dir,
            env: { ...process.env, PYTHONUNBUFFERED: "1" },
          });
          let out = "";
          let err = "";
          child.stdout.on("data", (d) => (out += d.toString()));
          child.stderr.on("data", (d) => (err += d.toString()));
          child.on("close", (code) => {
            if (code !== 0) console.error("[run-scraper] python stderr:", err);
            resolve({ exitCode: code ?? 1, stdout: out, stderr: err });
          });
          child.on("error", (e) => {
            resolve({ exitCode: 1, stdout: "", stderr: String(e) });
          });
        });

        if (exitCode !== 0) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            error: "Scraper failed",
            exit_code: exitCode,
            stderr: stderr.slice(-2000),
          }));
          return;
        }

        // The scraper writes JSON to stdout — parse + re-serialize to validate
        try {
          const parsed = JSON.parse(stdout);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(parsed));
        } catch {
          // stdout wasn't valid JSON — return raw
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(stdout);
        }
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          error: err instanceof Error ? err.message : "Scraper error",
        }));
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
      return;
    }

    // ── 404 ─────────────────────────────────────────────────────────────────
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", path }));
  } catch (err) {
    console.error("[engine] unhandled error:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: err instanceof Error ? err.message : "Internal error",
    }));
  }
});

// ── socket.io relay (same httpServer) ────────────────────────────────────────
const io = new Server(httpServer, {
  path: "/socket.io",
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingTimeout: 60000,
  pingInterval: 25000,
});

io.on("connection", (socket) => {
  socket.on("subscribe:scan", (scanId: string) => socket.join(`scan:${scanId}`));
  socket.on("unsubscribe:scan", (scanId: string) => socket.leave(`scan:${scanId}`));
  socket.on("subscribe:engagement", (engagementId: string) => socket.join(`engagement:${engagementId}`));
  socket.on("unsubscribe:engagement", (engagementId: string) => socket.leave(`engagement:${engagementId}`));
  socket.on("subscribe:global", () => socket.join("global"));

  // Producer (Vercel) can still emit events via socket.io-client if needed
  socket.on("pipeline:event", (event: { scanId?: string }) => {
    if (!event?.scanId) return;
    io.to(`scan:${event.scanId}`).emit("pipeline:event", event);
    io.to("global").emit("pipeline:event", event);
  });
  socket.on("redagent:event", (event: { engagementId?: string }) => {
    if (!event?.engagementId) return;
    io.to(`engagement:${event.engagementId}`).emit("redagent:event", event);
    io.to("global").emit("redagent:event", event);
  });
});

httpServer.listen(PORT, () => {
  console.log(`[guardianx-engine] HTTP + socket.io listening on :${PORT}`);
  console.log(`[guardianx-engine] Health: http://localhost:${PORT}/healthz`);
  console.log(`[guardianx-engine] socket.io path: /socket.io`);
  console.log(`[guardianx-engine] Auth: ${ENGINE_INTERNAL_KEY ? "enabled" : "DISABLED (set ENGINE_INTERNAL_KEY)"}`);
});

process.on("SIGTERM", () => httpServer.close(() => process.exit(0)));
process.on("SIGINT", () => httpServer.close(() => process.exit(0)));
