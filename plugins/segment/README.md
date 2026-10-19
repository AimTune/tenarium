# segment

Sends Tenarium data to [Segment](https://segment.com) through the HTTP Tracking API
(`POST /v1/batch`, write key as basic auth username):

| Call | From | Details |
|---|---|---|
| `group` | `tenant.*` events with a tenant (`group_events`) | `groupId` = tenant ID; traits `name`, `slug`, `plan`, `status`, `status_reason`, `tenant_id`, `parent_id`, `created_at`, `label_<key>`, `deleted` on `tenant.deleted` |
| `identify` | `user.*` events (`identify_users`) | `userId` = user ID; traits `email`, `name`, `status`, `email_verified`, `created_at`, `deleted` |
| `group` (membership) | `tenant.member_added/updated` (`link_members`) | links `userId` (the member's user) to the tenant's group; `context.traits` has `role` and `email`. Invited members without a user are skipped. |
| `track` | `track_events` | `event` = `event_names[type]` or the type; properties `event_type`, `event_id`, `actor`, `tenant_id` plus a compact payload subset (plan, previous plan, status, metric values, role); `context.groupId` = tenant ID |

## Configuration

```yaml
plugins:
  - plugin: segment
    config:
      write_key: ${SEGMENT_WRITE_KEY}
      api_url: https://api.segment.io           # EU: https://events.eu1.segmentapis.com
      track_events: ["tenant.created", "tenant.plan_changed", "tenant.deleted"]
      event_names:
        tenant.created: Tenant Created
        tenant.plan_changed: Plan Changed
      user_actor_prefixes: ["session"]
```

| Key | Type | Default | Description |
|---|---|---|---|
| `write_key` (required) | string | | Source write key. |
| `api_url` | URL | `https://api.segment.io` | Tracking API base. |
| `timeout` | duration | `10s` | Per request. |
| `group_events` | list of globs | `["tenant.*"]` | Events that send a tenant group call. `[]` disables. |
| `identify_users` | bool | `true` | Identify calls for `user.*`. |
| `link_members` | bool | `true` | Membership group calls. |
| `track_events` | list of globs | none | Events sent as track calls. |
| `event_names` | map | | Track event names by type. |
| `user_actor_prefixes` | list | none | Authenticators whose actor subject is a Tenarium user ID (`<authenticator>:<user id>`). Track and group calls caused by them use that `userId`. |
| `include_labels` | bool | `true` | Add tenant labels as `label_<key>` traits. |
| `batch_size` | int | `100` | Max messages per request (1-500). |

Each call kind has its own subscription (`group`, `identify`, `members`, `track`).

## Identity

Messages without a known user use `anonymousId` `tenant:<tenant id>` (or `tenarium` for
platform events), so system-caused calls do not merge into one anonymous profile.

## Delivery

- `messageId` is `<event id>:<kind>` (`group`, `identify`, `member`, `track`). Segment drops
  messages it has already seen, so redeliveries after a retry are harmless.
- `timestamp` is the event time; `sentAt` the request time.
- **Batching:** a delivery is sent at once when no request is in flight; deliveries arriving
  meanwhile (from the other subscriptions) share the next request, up to `batch_size` messages
  and Segment's 500 KB request limit. No delivery waits for a timer. A handler returns only when
  the request carrying its message was accepted, so at-least-once delivery holds; a failed
  request fails every handler in it and they are retried.
- Messages over Segment's 32 KB limit (e.g. huge labels) fail and are dead-lettered.
- `Stop` waits for an in-flight request.

## Health

The Tracking API has no endpoint that checks a write key without recording data, so `/readyz`
does not probe Segment. A wrong key shows up as failing deliveries (HTTP 401).
