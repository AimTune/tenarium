# paddle

Keeps [Paddle Billing](https://developer.paddle.com/api-reference/overview) customers and subscriptions in step
with Tenarium tenants, and suspends, resumes or re-plans tenants from Paddle notifications. It talks to the
Paddle REST API directly (no SDK) and stores nothing locally.

Paddle Billing has **no API to create a subscription**: a subscription only comes into being when a customer
completes a checkout (or pays a transaction). The plugin therefore manages customers and *existing*
subscriptions; the first purchase is left to your application's checkout (see [Checkout](#checkout)).

## Configuration

```yaml
plugins:
  - plugin: paddle
    config:
      api_key: pdl_live_apikey_...
      webhook_secret: pdl_ntfset_...
      environment: production          # or sandbox
      plans:
        pro: pri_01h8...pro
        enterprise: pri_01h8...ent
      customer_email_template: '{{index .Labels "billing_email"}}'
      suspend_on_past_due: true
      cancel_on_delete: next_billing_period
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `api_key` | string | (required) | Paddle API key, sent as `Authorization: Bearer`. |
| `webhook_secret` | string | (required) | Secret key of the notification destination (`pdl_ntfset_...`). |
| `environment` | `production` \| `sandbox` | `production` | Selects `https://api.paddle.com` or `https://sandbox-api.paddle.com`. |
| `api_base` | URL | from `environment` | Overrides the API URL (absolute http(s)). |
| `timeout` | duration | `15s` | Timeout per API request. |
| `plans` | map plan → price ID | `{}` | Tenarium plan ID → Paddle price ID (`pri_...`). Tenants on other plans are "unbilled". A price may map to one plan only. |
| `create_customers` | bool | `true` | Create missing customers. When `false`, only an existing customer with the tenant's billing email is used (and linked). |
| `customer_email_template` | template | `{{index .Labels "billing_email"}}` | Renders the customer email (Paddle requires one). An empty result means the tenant gets no customer; this is logged, not an error. |
| `suspend_on` | list of event types | `[subscription.canceled, subscription.paused]` | Notification types that suspend the tenant. Non-subscription types (e.g. `transaction.payment_failed`) are resolved through `custom_data` / `customer_id`. |
| `suspend_on_past_due` | bool | `false` | Also suspend when a subscription is `past_due`. |
| `resume_on_payment` | bool | `true` | Resume billing-suspended tenants on `transaction.completed` or when the subscription is `active`/`trialing` again. |
| `sync_plan_from_paddle` | bool | `true` | Move the tenant to the plan mapped to a price changed in Paddle. |
| `cancel_on_delete` | `immediately` \| `next_billing_period` | `immediately` | `effective_from` used when a deleted tenant's subscriptions are canceled. |
| `proration_billing_mode` | enum | `prorated_immediately` | Used for price changes: `prorated_immediately`, `prorated_next_billing_period`, `full_immediately`, `full_next_billing_period`, `do_not_bill`. |

### Template data

`customer_email_template` is a Go `text/template` (option `missingkey=error`) executed against the tenant:
`{{.ID}}`, `{{.Slug}}`, `{{.Name}}`, `{{.Plan}}`, `{{.ParentID}}`, `{{index .Labels "x"}}` (a missing label
renders empty). The result is trimmed; a result without `@` is treated as empty. Example:
`billing+{{.Slug}}@example.com`.

## Linking tenants and Paddle objects

Customers and subscriptions carry `custom_data`:

```json
{"tenarium_tenant_id": "<tenant id>", "tenarium_slug": "<slug>"}
```

Paddle cannot filter lists by `custom_data`, and its `search` parameter is fuzzy. The plugin therefore finds a
tenant's customer by **billing email** (`GET /customers?email=...`; emails are unique per Paddle account) and
accepts it only if its `custom_data.tenarium_tenant_id` is the tenant — or is absent, in which case the customer
is claimed (its `custom_data` is merged, other keys kept). A customer with the same email that belongs to
another tenant is never touched (a warning is logged).

In the other direction (notifications), the tenant is taken from the object's `custom_data`, falling back to
the customer's (`GET /customers/{customer_id}`).

## Tenarium → Paddle (subscription `sync`)

| Event | Action |
| --- | --- |
| `tenant.created` | Find or create the customer (`POST /customers {email, name, custom_data}`); then as `tenant.plan_changed`. |
| `tenant.plan_changed` | Find the plan subscription (`GET /subscriptions?customer_id=...&status=active,trialing,past_due,paused`). Billed plan: `PATCH /subscriptions/{id}` with the new price (other items such as add-ons are kept) and `proration_billing_mode`. Unbilled plan: cancel immediately. Billed plan without a subscription: log that the customer has to check out. |
| `tenant.updated` | When name, slug or billing email changed: `PATCH /customers/{id}`. A changed billing email is followed (the customer is found by the previous email and moved). |
| `tenant.deleted` | Cancel all live subscriptions (`POST /subscriptions/{id}/cancel {effective_from}`); the customer is kept. |

`tenant.created` and `tenant.plan_changed` act on the tenant's **current** plan (re-read from the host), not the
plan in the event, so a delayed event never pushes a stale plan back to Paddle.

A plan subscription is one tagged with the tenant ID or one with an item on a price from `plans`.

## Paddle → Tenarium (webhook)

Create a notification destination in Paddle (Developer tools → Notifications) pointing to

```
https://<tenarium>/v1/plugins/<instance>/public/webhook
```

subscribed to at least `subscription.*` and `transaction.completed` (plus anything you add to `suspend_on`),
and put its secret key in `webhook_secret`.

Requests are verified with the `Paddle-Signature` header (`ts=<unix>;h1=<hex>`): `h1` is HMAC-SHA256 of
`<ts>:<raw body>` keyed with the secret; several `h1` values (secret rotation) are accepted; timestamps more
than 5 minutes off are rejected. The exported `Sign` and `VerifySignature` helpers implement this.

| Notification | Action |
| --- | --- |
| `subscription.*` (`created`, `updated`, `activated`, `canceled`, `paused`, `resumed`, `past_due`, `trialing`, `imported`) | The subscription is re-read (`GET /subscriptions/{id}`) so out-of-order notifications act on the current state. Plan sync: if the mapped plan of its price differs from the tenant's plan (and the plan exists), the tenant's plan is changed. Then: a type in `suspend_on` suspends unless the subscription is healthy again (for `subscription.canceled`, also unless another plan subscription is healthy); `past_due` suspends with `suspend_on_past_due`; `active`/`trialing` resumes with `resume_on_payment`. |
| `transaction.completed` | With `resume_on_payment`, resumes the tenant unless its subscription (`subscription_id`) is still not `active`/`trialing`. |
| other types in `suspend_on` | Suspend the tenant resolved from `custom_data` / `customer_id`. |
| anything else | Acknowledged (200) and ignored. |

Suspension reasons are `billing: <event type>` (with ` (past_due)` appended when a non-`past_due` event finds
the subscription past due).

Rules (identical to the Stripe plugin):

- Only `active` tenants on a billed plan are suspended. Tenants on unbilled plans are never suspended, so
  canceling the subscription after a downgrade to a free plan is harmless.
- Only tenants whose status reason starts with `billing:` are resumed; other suspensions are left alone.
- Host rejections (hooks vetoing a suspend/resume/plan change) are logged and swallowed.
- Plan sync from Paddle only happens when the mapped plan differs from the tenant's plan; a change made by
  Tenarium already matches, which prevents loops.

Responses: 200 for handled, duplicate or irrelevant notifications; 400 for a bad signature, expired timestamp
or invalid payload; 500 when handling failed (Paddle retries).

## Idempotency

- Tenant events are delivered at least once. Every step reads the current Paddle state first, so redeliveries
  converge. Paddle has no idempotency keys, but customer emails are unique: a duplicate `POST /customers`
  fails with `409 customer_already_exists`, and the plugin then uses the customer named in the error.
- Notification `event_id`s are remembered in a bounded in-memory set (10,000) and marked only after
  successful handling; duplicates are answered with `{"received":true,"duplicate":true}`. Across restarts,
  the state-based handling keeps duplicates harmless.

## Tenant billing route

`GET /v1/plugins/<instance>/tenants/{tenant}` (ID or slug) returns the customer and plan subscription:

```json
{"customer_id":"ctm_...","email":"billing@acme.test","subscription_id":"sub_...","status":"active",
 "price":"pri_...","current_period_end":"2030-01-01T00:00:00Z","next_billed_at":"2030-01-01T00:00:00Z"}
```

It requires `tenants:read` on the tenant (`Host.Authorize`); callers without access get 404.

## Health

`Health` calls `GET /event-types`, a cheap authenticated request that validates the API key.

## Checkout

Because Paddle creates subscriptions only through checkout, open Paddle.js checkout for the tenant with the
tenant's customer (or billing email) and pass the link in custom data so the resulting transaction and
subscription are linked:

```js
Paddle.Checkout.open({
  items: [{ priceId: "pri_...pro", quantity: 1 }],
  customer: { email: "billing@acme.test" },          // or { id: "ctm_..." }
  customData: { tenarium_tenant_id: "<tenant id>" },
});
```

Without `customData`, the tenant is still found through the customer's `custom_data`, as long as the checkout
used the tenant's customer.

## Limitations

- No subscription creation from Tenarium (Paddle API restriction); a billed plan without a subscription is
  only logged. No usage/metering export.
- Customers are found by billing email. A tenant without a billing email has no customer; changing the email
  while the plugin is not running (no `tenant.updated` delivered) loses the link until the email is restored.
- Paddle notifications carry no previous values, so plan sync runs on every live subscription notification
  (guarded by the plan comparison) rather than only on price changes.
- Changes to paused or past-due subscriptions may be refused by Paddle; such errors are returned so the event
  is retried.
- Subscription and customer listings read a single page of up to 200 entries.
