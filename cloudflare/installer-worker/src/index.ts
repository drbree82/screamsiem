interface Enrollment {
  controller?: {
    public_key: string;
    controller_address: string;
    controller_user: string;
    updated_at: string;
  };
  hosts: Record<string, Record<string, unknown>>;
  updated_at: string;
}

interface Env {
  ENROLLMENTS: KVNamespace;
  ASSETS: Fetcher;
}

const TTL = 60 * 60 * 24 * 7;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

async function keyFor(code: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
  return `enroll:${Array.from(new Uint8Array(bytes)).map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

function validCode(code: string): boolean {
  return /^[A-Za-z0-9._:-]{12,128}$/.test(code);
}

function validPublicKey(value: unknown): value is string {
  return typeof value === "string" && value.length <= 1000 && /^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?$/.test(value);
}

async function readEnrollment(env: Env, code: string): Promise<Enrollment> {
  return (await env.ENROLLMENTS.get(await keyFor(code), "json") as Enrollment | null) || { hosts: {}, updated_at: new Date().toISOString() };
}

async function writeEnrollment(env: Env, code: string, data: Enrollment): Promise<void> {
  data.updated_at = new Date().toISOString();
  await env.ENROLLMENTS.put(await keyFor(code), JSON.stringify(data), { expirationTtl: TTL });
}

async function api(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] !== "v1" || parts[1] !== "enroll" || !parts[2] || !validCode(parts[2])) return json({ error: "invalid enrollment path" }, 400);
  const code = parts[2];
  const data = await readEnrollment(env, code);

  if (request.method === "GET" && parts.length === 3) {
    return json({ controller: data.controller || null, hosts: Object.values(data.hosts), updated_at: data.updated_at });
  }
  if (request.method !== "POST" || parts.length !== 4) return json({ error: "not found" }, 404);
  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; } catch { return json({ error: "invalid JSON" }, 400); }

  if (parts[3] === "controller") {
    if (!validPublicKey(body.public_key)) return json({ error: "invalid ssh-ed25519 public key" }, 400);
    data.controller = {
      public_key: body.public_key,
      controller_address: typeof body.controller_address === "string" ? body.controller_address.slice(0, 255) : "",
      controller_user: typeof body.controller_user === "string" ? body.controller_user.slice(0, 64) : "screamsiem",
      updated_at: new Date().toISOString(),
    };
    await writeEnrollment(env, code, data);
    return json({ status: "controller_registered" });
  }
  if (parts[3] === "hosts") {
    if (typeof body.host_id !== "string" || typeof body.hostname !== "string") return json({ error: "host_id and hostname are required" }, 400);
    const hostId = body.host_id.slice(0, 128);
    data.hosts[hostId] = {
      host_id: hostId,
      hostname: body.hostname.toString().slice(0, 255),
      addresses: Array.isArray(body.addresses) ? body.addresses.filter((x): x is string => typeof x === "string").slice(0, 16) : [],
      ssh_port: Number.isInteger(body.ssh_port) ? body.ssh_port : 22,
      ssh_user: typeof body.ssh_user === "string" ? body.ssh_user.slice(0, 64) : "screamsiem",
      os: typeof body.os === "string" ? body.os.slice(0, 4000) : "",
      kernel: typeof body.kernel === "string" ? body.kernel.slice(0, 255) : "",
      enrolled_at: data.hosts[hostId]?.enrolled_at || new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
    };
    await writeEnrollment(env, code, data);
    return json({ status: "host_registered", host_id: hostId });
  }
  return json({ error: "not found" }, 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/v1/")) return api(request, env);
    if (url.pathname === "/" || url.pathname === "/healthz") return json({ service: "screamsiem-installer", status: "ok" });
    return env.ASSETS.fetch(request);
  },
};
