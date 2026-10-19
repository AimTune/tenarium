// A fake OpenID provider and DNS for the identity tests, run by the global setup.
//
// One HTTP server hosts any number of issuers ("realms"): the issuer
// <url>/<realm> serves discovery, JWKS, an authorize endpoint that signs the
// user in at once and redirects back with a code, and a token endpoint that
// checks the code, redirect URI, PKCE verifier and client credentials and
// returns an RS256-signed ID token carrying the request's nonce. Tests use their
// own realm (an SSO connection) or the shared "social" realm.
//
// Who signs in is chosen by the browser: a cookie (USER_COOKIE, see
// fakes/client.ts) holds the user's claims, so tests running in parallel in
// separate browser contexts do not interfere. Without it, login_hint is used as
// a verified email.
//
// The server also answers TXT lookups for Tenarium's domain verification
// (tests/ui/testserver resolves through it): POST /dns/txt {name, value} adds
// a record, GET /dns/txt?name= lists them.
import crypto from "node:crypto";
import http from "node:http";
import type net from "node:net";

export const USER_COOKIE = "fake_idp_user";
export const CLIENT_SECRET = "fake-idp-client-secret";

// FakeUser is what the provider asserts; email_verified is left out of the ID
// token when undefined.
export type FakeUser = { email: string; email_verified?: boolean; name?: string; sub?: string };

type Grant = {
  realm: string; clientID: string; redirectURI: string; challenge: string; nonce: string; user: FakeUser; expires: number;
};

export type FakeIdP = { url: string; close: () => Promise<void> };

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

export async function startFakeIdP(): Promise<FakeIdP> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = crypto.randomBytes(8).toString("hex");
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
  const codes = new Map<string, Grant>();
  const txt = new Map<string, string[]>();
  let base = "";

  const sign = (claims: object) => {
    const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
    const body = b64u(JSON.stringify(claims));
    return `${head}.${body}.${b64u(crypto.sign("sha256", Buffer.from(`${head}.${body}`), privateKey))}`;
  };

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url || "/", base);
    const send = (status: number, body: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers });
      res.end(body === undefined ? "" : JSON.stringify(body));
    };
    const readBody = async () => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      return Buffer.concat(chunks).toString("utf8");
    };
    try {
      if (u.pathname === "/dns/txt") {
        if (req.method === "POST") {
          const { name, value } = JSON.parse(await readBody());
          const key = String(name).toLowerCase();
          txt.set(key, [...(txt.get(key) || []), String(value)]);
          return send(204, undefined);
        }
        return send(200, txt.get((u.searchParams.get("name") || "").toLowerCase()) || []);
      }
      const m = /^\/([a-z0-9-]+)(\/.*)$/.exec(u.pathname);
      if (!m) return send(404, { error: "not_found" });
      const [, realm, path] = m;
      const issuer = `${base}/${realm}`;
      switch (`${req.method} ${path}`) {
        case "GET /.well-known/openid-configuration":
          return send(200, {
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            jwks_uri: `${issuer}/jwks`,
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
            code_challenge_methods_supported: ["S256"],
            token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          });
        case "GET /jwks":
          return send(200, { keys: [jwk] });
        case "GET /authorize":
          return authorize(realm, u, req, res);
        case "POST /token":
          return token(realm, issuer, new URLSearchParams(await readBody()), req, send);
      }
      return send(404, { error: "not_found" });
    } catch (e) {
      return send(400, { error: "invalid_request", error_description: String(e) });
    }
  });

  function authorize(realm: string, u: URL, req: http.IncomingMessage, res: http.ServerResponse) {
    const q = u.searchParams;
    const redirect = q.get("redirect_uri");
    if (!redirect || !q.get("client_id")) {
      res.writeHead(400).end("redirect_uri and client_id are required");
      return;
    }
    const back = new URL(redirect);
    if (q.get("state")) back.searchParams.set("state", q.get("state")!);
    const fail = (error: string) => {
      back.searchParams.set("error", error);
      res.writeHead(302, { Location: back.toString() }).end();
    };
    if (q.get("response_type") !== "code") return fail("unsupported_response_type");
    if (q.get("code_challenge_method") !== "S256" || !q.get("code_challenge")) return fail("invalid_request");
    if (!q.get("nonce") || !q.get("state") || !(q.get("scope") || "").split(" ").includes("openid")) return fail("invalid_request");
    const user = userFrom(req.headers.cookie) || (q.get("login_hint") ? { email: q.get("login_hint")!, email_verified: true } : null);
    if (!user) return fail("login_required");
    const code = crypto.randomBytes(18).toString("base64url");
    codes.set(code, {
      realm, clientID: q.get("client_id")!, redirectURI: redirect, challenge: q.get("code_challenge")!,
      nonce: q.get("nonce")!, user, expires: Date.now() + 60_000,
    });
    back.searchParams.set("code", code);
    res.writeHead(302, { Location: back.toString() }).end();
  }

  function token(realm: string, issuer: string, form: URLSearchParams, req: http.IncomingMessage,
    send: (status: number, body: unknown) => void) {
    const code = form.get("code") || "";
    const g = codes.get(code);
    codes.delete(code); // codes work once
    let [id, secret] = [form.get("client_id"), form.get("client_secret")];
    const basic = /^Basic (.+)$/.exec(req.headers.authorization || "");
    if (basic) [id, secret] = Buffer.from(basic[1], "base64").toString().split(":").map(decodeURIComponent);
    const verifier = form.get("code_verifier") || "";
    const ok = g && g.realm === realm && g.expires > Date.now() && form.get("grant_type") === "authorization_code" &&
      id === g.clientID && secret === CLIENT_SECRET && form.get("redirect_uri") === g.redirectURI &&
      crypto.createHash("sha256").update(verifier).digest("base64url") === g.challenge;
    if (!ok) return send(400, { error: "invalid_grant" });
    const now = Math.floor(Date.now() / 1000);
    const user = g.user;
    const claims: Record<string, unknown> = {
      iss: issuer, aud: g.clientID, sub: user.sub || `sub-${user.email}`, nonce: g.nonce,
      iat: now, exp: now + 300, email: user.email, name: user.name || user.email.split("@")[0],
    };
    if (user.email_verified !== undefined) claims.email_verified = user.email_verified;
    return send(200, { access_token: crypto.randomBytes(16).toString("hex"), token_type: "Bearer", expires_in: 300, id_token: sign(claims) });
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
  return {
    url: base,
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

function userFrom(cookie: string | undefined): FakeUser | null {
  for (const part of (cookie || "").split(";")) {
    const [k, v] = part.trim().split("=");
    if (k === USER_COOKIE && v) return JSON.parse(Buffer.from(v, "base64url").toString("utf8"));
  }
  return null;
}
