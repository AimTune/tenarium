# Tenant webhooks

Tenants can register their own HTTP endpoints to receive their own events, without a platform
operator configuring anything. (To send *all* events to one platform endpoint, use the
[webhook plugin](plugins/README.md) instead.)

```sh
curl -sX POST $API/v1/tenants/acme/webhooks -H "$AUTH" \
  -d '{"url":"https://hooks.acme.com/tenarium","types":["tenant.*","member.*"],"description":"CRM sync"}'
# → {"webhook": {"id": "...", ...}, "secret": "whsec_..."}   the secret is shown only once
```

| Endpoint | Purpose |
|---|---|
| `GET/POST /v1/tenants/{id}/webhooks` | list, register (max `webhooks.max_per_tenant`) |
| `GET/PATCH/DELETE /v1/tenants/{id}/webhooks/{webhook}` | inspect, change `url`/`types`/`description`/`enabled`, delete |
| `POST .../rotate-secret` | new signing secret (shown once) |
| `POST .../test` | send a `webhook.test` event now and return the result |
| `GET .../deliveries` | delivery log, newest first (`before`, `limit`) |
| `POST .../deliveries/{delivery}/redeliver` | send a logged delivery again |

Permissions: `webhooks:read` and `webhooks:write`; tenant owners and admins have both.

## What is sent

Every event of the tenant whose type matches one of `types` (glob patterns; empty means all)
is POSTed as a [CloudEvent](https://cloudevents.io) (`Content-Type:
application/cloudevents+json`), the same JSON the event log holds. Events about child tenants
are not included; register webhooks on each tenant that needs them.

Requests follow [Standard Webhooks](https://www.standardwebhooks.com):

| Header | Value |
|---|---|
| `webhook-id` | the event ID: the same on retries and redeliveries, so deduplicate on it |
| `webhook-timestamp` | Unix seconds |
| `webhook-signature` | `v1,<base64 HMAC-SHA256 of "id.timestamp.body">`, keyed with the base64-decoded part of the `whsec_` secret |

Verifying in Go:

```go
func verify(secret string, r *http.Request, body []byte) bool {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	ts, _ := strconv.ParseInt(r.Header.Get("webhook-timestamp"), 10, 64)
	if math.Abs(float64(time.Now().Unix()-ts)) > 300 {
		return false // replayed or badly skewed
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(r.Header.Get("webhook-id") + "." + r.Header.Get("webhook-timestamp") + "."))
	mac.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(r.Header.Get("webhook-signature")))
}
```

The official Standard Webhooks libraries (JavaScript, Python, Go, ...) verify these headers
directly.

## Delivery, retries and disabling

- Any 2xx answer is success. Redirects are not followed and count as failures.
- Each event is tried `webhooks.attempts` times (default 3) with a short backoff, each attempt
  limited by `webhooks.timeout` (default 10s). Endpoints are independent: a slow or failing
  one does not delay or duplicate deliveries to the others.
- Every delivery is logged with status code, error, attempts and duration, and kept for
  `webhooks.delivery_retention` (default 30 days).
- After `webhooks.max_failures` consecutive failed events (default 50) the webhook is disabled
  and a `webhook.disabled` event is emitted. Re-enabling it (`PATCH {"enabled": true}`) resets
  the counter. Events that happened while it was disabled are not sent; redeliver them from the
  log if needed.
- Delivery is at least once: deduplicate on `webhook-id`.

Webhook changes are audited as `webhook.created`, `webhook.updated`, `webhook.deleted` and
`webhook.disabled` (the secret is never part of an event).

## Security

Tenants choose the URLs, so Tenarium refuses to call into your network: URLs must use https,
and connections to loopback, private, link-local (cloud metadata), CGNAT and multicast
addresses are refused when connecting, after DNS resolution, so a public name pointing at an
internal address does not get through either. Proxies from the environment are ignored for the
same reason. `webhooks.allow_http` and `webhooks.allow_private_networks` lift these checks for
development only.
