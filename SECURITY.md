# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately rather than in public issues, either:

- through GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab), or
- by email to the security contact: **hamzaagareng@gmail.com**.

Include steps to reproduce and the affected version or commit. We aim to acknowledge reports
within a few days and to agree on a disclosure date with you.

## Scope

Areas of particular interest: authorization bypasses (especially the tenant-scope rule and
platform-only actions), authentication (tokens, SSO/SAML, passkeys, the OpenID provider,
impersonation), the external plugin protocol, the WASM sandbox, SSRF protections and secrets
handling. See [.oss-scanner/threat_model.md](.oss-scanner/threat_model.md) for the full threat
model.

## Supported versions

Tenarium has not had a tagged release yet; fixes go to `main`.
