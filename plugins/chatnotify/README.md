# chat-notify

Posts messages about Tenarium events to Slack and Microsoft Teams.

| Target `type` | Destination | Payload |
|---|---|---|
| `slack_webhook` | Slack incoming webhook URL | `{"text": ...}` (mrkdwn) |
| `slack_bot` | `chat.postMessage` with a bot token (`xoxb-...`) and channel | `{"channel", "text"}` |
| `teams_webhook` | Teams incoming webhook (Office 365 connector) | Adaptive Card message |
| `teams_workflow` | Teams Workflows / Power Automate "When a Teams webhook request is received" URL | Adaptive Card message |

Each target has its own subscription (`notify-<name>`), so retries and failures of one chat
service never delay the others.

## Configuration

```yaml
plugins:
  - plugin: chat-notify
    config:
      events: ["tenant.created", "tenant.suspended", "tenant.provisioning_failed"]
      title: "Tenarium: {{.Event.Type}}"
      templates:
        "tenant.quota_exceeded": "{{.TenantLabel}} hit its {{.Quota.Metric}} limit ({{.Quota.Limit}})"
        "tenant.member_*": "{{.Member.Email}}: {{.Event.Type}}"
      timeout: 10s
      targets:
        - name: ops
          type: slack_webhook
          url: ${SLACK_OPS_WEBHOOK}
        - name: alerts
          type: slack_bot
          token: ${SLACK_BOT_TOKEN}
          channel: C0123456789
        - name: billing
          type: teams_workflow
          url: ${TEAMS_BILLING_WORKFLOW_URL}
          events: ["tenant.suspended", "tenant.resumed"]
          template: "{{.TenantLabel}}: {{.Event.Type}} {{with .Tenant}}{{.StatusReason}}{{end}}"
          rate_limit: {per_minute: 10, burst: 5}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `targets` (required) | list | | At least one target, see below. |
| `events` | list of globs | see below | Event types for targets without their own `events`. |
| `templates` | map glob → template | built-in | Message templates by event type. Exact types win over globs; globs are tried in sorted order. |
| `title` | template | `Tenarium: {{.Event.Type}}` | Teams card heading; bold first line in Slack. |
| `timeout` | duration | `10s` | Per request. |

Default events: `tenant.created`, `tenant.suspended`, `tenant.resumed`, `tenant.deleted`,
`tenant.provisioning_failed`, `tenant.deprovisioning_failed`, `tenant.quota_exceeded`,
`tenant.usage_threshold_reached`.

### Targets

| Key | Description |
|---|---|
| `name` (required) | `^[a-z0-9][a-z0-9_-]*$`, unique. |
| `type` (required) | `slack_webhook`, `slack_bot`, `teams_webhook` or `teams_workflow`. |
| `url` | Webhook or Workflows URL (all types but `slack_bot`). Treat it as a secret. |
| `token`, `channel` | `slack_bot` only. The bot needs `chat:write` (and must be in the channel). |
| `api_base` | `slack_bot` only; default `https://slack.com/api`. |
| `events` | Overrides `events` for this target. |
| `template` | Overrides every message template for this target. |
| `rate_limit` | `per_minute` (default 30) and `burst` (default `per_minute`). |

## Templates

Templates use Go `text/template`. They are executed with:

| Field | Set for |
|---|---|
| `.Event` | always: `.Type`, `.ID`, `.Actor`, `.Time`, `.TenantID`, `.Subject`, `.Seq` |
| `.Tenant`, `.Previous` | `tenant.*` events (`sdk.Tenant`: `.ID .Slug .Name .Plan .Status .StatusReason .Labels`); for member and usage events the tenant is looked up |
| `.Member` | `tenant.member_*` (`.Email .Role .Status .UserID`) |
| `.User` | `user.*` (`.Email .Name .Status`) |
| `.Plan` | `plan.*` (`.ID .Name`) |
| `.Usage` | `tenant.usage_threshold_reached`, `tenant.usage_period_closed` (`.Metric .Value .Limit .Percent .Period`) |
| `.Quota` | `tenant.quota_exceeded` (`.Metric .Current .Requested .Limit`) |
| `.Data` | the raw payload as a map |
| `.TenantLabel` | "Name (slug)", or the tenant ID |

Functions: `upper`, `lower`, `join SEP LIST`, `default DEF VALUE`, `json VALUE`,
`truncate N STRING`, `time TIME` (UTC, minutes).

Templates are parsed at startup. If a template fails at run time (for example `.Tenant.Name` on
an event without a tenant) or renders nothing, a generic message
(`<type> for tenant <label> by <actor>`) is sent instead and a warning is logged, so a template
mistake never blocks notifications. The built-in templates use no markup, so they read the same
in Slack and Teams.

## Delivery and rate limiting

- Delivery is at least once. Each target remembers the IDs of the last 1000 events it posted,
  so a redelivered event is not posted twice.
- Non-2xx responses, Slack `{"ok": false}` responses, HTTP 429 and failures that legacy Teams
  connectors report in a 200 body are errors, and the event is retried with backoff.
- Each target is a token bucket. Notifications over the limit are **dropped** with a warning
  instead of retried, so a burst of events (bulk imports, mass suspensions) cannot flood a
  channel or the retry queue. The next message that gets through ends with
  "(N earlier notification(s) suppressed by the rate limit)". A failed post gives its token
  back, so retries are not limited twice.

## Health

`/readyz` calls Slack's `auth.test` for `slack_bot` targets. Webhook URLs offer no check without
side effects, so they are not probed.
