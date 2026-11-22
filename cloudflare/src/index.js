/**
 * Software Factory Signal Queue Worker (Cloudflare Workers + D1 + R2).
 *
 * Security model:
 * - Deployed with workers_dev = false behind Cloudflare Access (Service Auth).
 * - Stores raw logs only in R2 (RAW_LOGS) and exposes only sanitized Signal JSON v1,
 *   read-only telemetry query aggregates, and post-deploy recovery checks to the orchestrator.
 */

const VALID_KINDS = new Set(["feature", "bugfix", "security", "efficiency", "proposal"]);
const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const VALID_ACK_STATUSES = new Set([
  "dismissed",
  "auto_merged",
  "human_review",
  "resolved",
  "recovery_failed",
]);
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function rowToSignal(row, origin) {
  const signal = {
    schemaVersion: 1,
    id: row.id,
    source: row.source,
    repo: row.repo,
    kind: row.kind,
    severity: row.severity,
    title: row.title,
    summary: row.summary,
    evidence: JSON.parse(row.evidence_json || "{}"),
    dedupeKey: row.dedupe_key,
    createdAt: row.created_at,
    ackUrl: `${origin}/v1/signals/${encodeURIComponent(row.id)}/ack`,
  };
  if (row.recovery_json) {
    signal.recoveryCheck = JSON.parse(row.recovery_json);
  }
  return signal;
}

async function handleListSignals(request, env, url) {
  const status = url.searchParams.get("status") || "pending";
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 50), 1), 200);
  const { results } = await env.DB.prepare(
    `SELECT * FROM signals WHERE status = ? ORDER BY created_at ASC LIMIT ?`
  )
    .bind(status, limit)
    .all();

  const origin = url.origin;
  return json({
    signals: (results || []).map((row) => rowToSignal(row, origin)),
  });
}

async function handleCreateSignal(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const repo = String(body.repo || "").trim();
  const kind = String(body.kind || "bugfix").trim();
  const severity = String(body.severity || "medium").trim();
  const title = String(body.title || "").trim();
  const summary = String(body.summary || "").trim();
  const source = String(body.source || "open-observability-framework").trim();
  const dedupeKey = String(body.dedupeKey || "").trim();

  if (!REPO_RE.test(repo)) return json({ error: "Invalid repo" }, 400);
  if (!VALID_KINDS.has(kind)) return json({ error: "Invalid kind" }, 400);
  if (!VALID_SEVERITIES.has(severity)) return json({ error: "Invalid severity" }, 400);
  if (!title) return json({ error: "Missing title" }, 400);
  if (!dedupeKey) return json({ error: "Missing dedupeKey" }, 400);

  const existing = await env.DB.prepare(
    `SELECT id FROM signals WHERE dedupe_key = ? AND status = 'pending' LIMIT 1`
  )
    .bind(dedupeKey)
    .first();
  if (existing) {
    return json({ status: "deduplicated", id: existing.id }, 200);
  }

  const id = String(body.id || `sig-${crypto.randomUUID().slice(0, 12)}`).trim();
  const ts = nowIso();
  const evidenceJson = JSON.stringify(body.evidence && typeof body.evidence === "object" ? body.evidence : {});
  const recoveryJson =
    body.recoveryCheck && typeof body.recoveryCheck === "object"
      ? JSON.stringify(body.recoveryCheck)
      : null;

  await env.DB.prepare(
    `INSERT INTO signals
      (id, source, repo, kind, severity, title, summary, evidence_json, recovery_json, dedupe_key, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
  )
    .bind(id, source, repo, kind, severity, title, summary, evidenceJson, recoveryJson, dedupeKey, ts, ts)
    .run();

  return json(
    {
      status: "queued",
      id,
      ackUrl: `${url.origin}/v1/signals/${encodeURIComponent(id)}/ack`,
    },
    201
  );
}

async function handleAckSignal(request, env, signalId) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const status = String(body.status || "").trim();
  if (!VALID_ACK_STATUSES.has(status)) {
    return json({ error: `Unsupported ack status: ${status}` }, 400);
  }

  const ts = nowIso();
  const res = await env.DB.prepare(
    `UPDATE signals
     SET status = ?, run_id = ?, pr_url = ?, reason = ?, updated_at = ?
     WHERE id = ?`
  )
    .bind(
      status,
      body.runId ? String(body.runId) : null,
      body.prUrl ? String(body.prUrl) : null,
      body.reason ? String(body.reason) : null,
      ts,
      signalId
    )
    .run();

  if (!res.meta || res.meta.changes === 0) {
    return json({ error: "Signal not found" }, 404);
  }
  return json({ ok: true, id: signalId, status });
}

async function handleQuery(request, env, queryId) {
  if (request.method === "GET") {
    const row = await env.DB.prepare(`SELECT payload_json FROM telemetry_queries WHERE id = ?`)
      .bind(queryId)
      .first();
    if (!row) return json({ error: "Query reference not found" }, 404);
    return new Response(row.payload_json, {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }
  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }
    const ts = nowIso();
    await env.DB.prepare(
      `INSERT INTO telemetry_queries (id, payload_json, created_at, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at`
    )
      .bind(queryId, JSON.stringify(body), ts, ts)
      .run();
    return json({ ok: true, id: queryId });
  }
  return json({ error: "Method not allowed" }, 405);
}

async function handleRecovery(request, env, recoveryId) {
  if (request.method === "GET") {
    const row = await env.DB.prepare(
      `SELECT recovered, summary, metrics_json, updated_at FROM recovery_checks WHERE id = ?`
    )
      .bind(recoveryId)
      .first();
    if (!row) return json({ error: "Recovery check not found" }, 404);
    return json({
      id: recoveryId,
      recovered: Boolean(row.recovered),
      summary: row.summary,
      metrics: JSON.parse(row.metrics_json || "{}"),
      updatedAt: row.updated_at,
    });
  }
  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }
    const ts = nowIso();
    await env.DB.prepare(
      `INSERT INTO recovery_checks (id, recovered, summary, metrics_json, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         recovered = excluded.recovered,
         summary = excluded.summary,
         metrics_json = excluded.metrics_json,
         updated_at = excluded.updated_at`
    )
      .bind(
        recoveryId,
        body.recovered ? 1 : 0,
        String(body.summary || ""),
        JSON.stringify(body.metrics && typeof body.metrics === "object" ? body.metrics : {}),
        ts
      )
      .run();
    return json({ ok: true, id: recoveryId });
  }
  return json({ error: "Method not allowed" }, 405);
}

async function handleRawLogIngest(request, env) {
  if (!env.RAW_LOGS) {
    return json({ error: "RAW_LOGS bucket not bound" }, 500);
  }
  const ts = nowIso();
  const datePrefix = ts.slice(0, 10);
  const service = (request.headers.get("x-service-name") || "default").replace(/[^A-Za-z0-9_.-]/g, "_");
  const key = `${datePrefix}/${service}/${ts}-${crypto.randomUUID()}.log`;
  const contentType = request.headers.get("content-type") || "application/x-ndjson";
  await env.RAW_LOGS.put(key, request.body, {
    httpMetadata: { contentType },
    customMetadata: { service, ingestedAt: ts },
  });
  return json({ ok: true, key }, 201);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/v1/health" && request.method === "GET") {
      return json({ ok: true, service: "sf-signal-queue", time: nowIso() });
    }

    if (path === "/v1/signals") {
      if (request.method === "GET") return handleListSignals(request, env, url);
      if (request.method === "POST") return handleCreateSignal(request, env, url);
      return json({ error: "Method not allowed" }, 405);
    }

    const ackMatch = path.match(/^\/v1\/signals\/([^/]+)\/ack$/);
    if (ackMatch && request.method === "POST") {
      return handleAckSignal(request, env, decodeURIComponent(ackMatch[1]));
    }

    const queryMatch = path.match(/^\/v1\/queries\/([^/]+)$/);
    if (queryMatch) {
      return handleQuery(request, env, decodeURIComponent(queryMatch[1]));
    }

    const recoveryMatch = path.match(/^\/v1\/recovery\/([^/]+)$/);
    if (recoveryMatch) {
      return handleRecovery(request, env, decodeURIComponent(recoveryMatch[1]));
    }

    if (path === "/v1/logs" && request.method === "POST") {
      return handleRawLogIngest(request, env);
    }

    return json({ error: "Not found" }, 404);
  },
};
