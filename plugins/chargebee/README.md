# chargebee

Keeps Chargebee customers and subscriptions in step with tenants, and suspends, resumes or
re-plans tenants from Chargebee webhooks. It uses Chargebee API v2 (Product Catalog 2.0) directly,
with the same semantics as the `stripe` plugin.

## Configuration

```yaml
plugins:
  - plugin: chargebee
    config:
      site: acme                         # https://acme.chargebee.com
      api_key: ${CHARGEBEE_API_KEY}
      webhook_username: tenarium
      webhook_password: ${CHARGEBEE_WEBHOOK_PASSWORD}
      plans:                             # Tenarium plan: Chargebee item price ID
        pro: pro-USD-Monthly
        enterprise: enterprise-USD-Yearly
      tenant_id_field: cf_tenarium_tenant_id
      suspend_on_payment_failed: true
      cancel_on_delete: end_of_term
```

| Key | Type | Default | Description |
|---|---|---|---|
| `site` (required) | string | | Site name (`^[a-z0-9-]+$`). |
| `api_key` (required) | string | | API key, sent as the basic auth username. |
| `api_base` | URL | `https://{site}.chargebee.com/api/v2` | Override (tests, proxies). |
| `timeout` | duration | `15s` | Per API request. |
| `webhook_username`, `webhook_password` (required) | string | | Basic auth credentials configured on the Chargebee webhook. |
| `plans` | map | none | Tenarium plan → item price ID. Tenants on other plans have no subscription. |
| `create_customers` | bool | `true` | Create missing customers. When off, only an existing customer whose ID is the tenant ID is used. |
| `suspend_on` | list | `subscription_cancelled`, `subscription_paused` | Event types that suspend the tenant. |
| `suspend_on_payment_failed` | bool | `false` | Also suspend on `payment_failed`. |
| `resume_on_payment` | bool | `true` | Resume billing-suspended tenants on `payment_succeeded` or when their subscription is healthy again. |
| `sync_plan_from_chargebee` | bool | `true` | Move the tenant to the plan mapped to an item price changed in Chargebee. |
| `cancel_on_delete` | enum | `immediately` | `immediately` or `end_of_term` for deleted tenants. |
| `tenant_id_field` | string | none | Customer custom field (`cf_...`, must exist in Chargebee) set to the tenant ID. |

## Tenarium → Chargebee (subscription `sync`)

| Event | Action |
|---|---|
| `tenant.created` | Create the customer (and, for a billed plan, the subscription via `subscription_for_items`). |
| `tenant.plan_changed` | Replace the subscription's items with the new item price (`update_for_items`, `replace_items_list`), create or reactivate the subscription, or cancel it immediately when the new plan is not billed. |
| `tenant.updated` | Set the customer's `company` and slug metadata when name or slug changed. |
| `tenant.deleted` | Cancel live subscriptions (`cancel_on_delete`). The customer is kept for its billing history. |

**Linking and idempotency.** Chargebee lets callers choose IDs, so the tenant ID is both the
customer ID and the plan subscription ID (customers and subscriptions are separate ID
namespaces). A redelivered event that creates an existing object gets `duplicate_entry`, which
is treated as success. Customers and subscriptions also carry
`meta_data {"tenarium_tenant_id", "tenarium_slug"}` and, with `tenant_id_field`, a custom field,
so objects created elsewhere (e.g. by hosted checkout) can be linked too. Other subscriptions of
the customer (add-ons) are left alone.

## Chargebee → Tenarium (webhooks)

In Chargebee (Settings → Webhooks), add `https://<tenarium>/v1/plugins/{instance}/public/webhook`
with basic authentication set to `webhook_username` / `webhook_password`. Credentials are
compared in constant time; wrong ones get 401.

- Event IDs are remembered (last 10,000) and only marked after successful handling; duplicates
  get 200. Handling failures return 500 so Chargebee retries. Unknown event types get 200.
- Subscription events act on the subscription's **current** state (it is re-fetched), so
  out-of-order events are harmless.
- `suspend_on` events suspend the tenant with reason `billing: <event type>` unless the
  subscription is healthy again (or another plan subscription of the customer is).
  `payment_failed` suspends with `suspend_on_payment_failed`.
- `subscription_resumed`, `subscription_activated`, `subscription_reactivated`,
  `subscription_renewed`, ... and `payment_succeeded` resume the tenant when the subscription is
  healthy and has no due invoices, but **only** if the tenant was suspended for billing (status
  reason starts with `billing:`).
- `subscription_created` / `subscription_changed` move the tenant to the plan mapped to the
  item price, only if it differs from the tenant's plan and exists in Tenarium. A change that
  came from Tenarium already matches, so there is no loop.
- Tenants on unbilled plans are never suspended for billing. Rejections by hooks are logged
  and not retried.

## Routes

`GET /v1/plugins/{instance}/tenants/{tenant}` returns the tenant's customer and subscription
(caller must be allowed `tenants:read` on the tenant).

## Health

`/readyz` lists one customer (`GET /customers?limit=1`), which checks the site and API key.
