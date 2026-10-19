-- W3C trace context of the request that produced each event, so consumers
-- can link their spans to it.
ALTER TABLE events ADD COLUMN traceparent text NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN tracestate text NOT NULL DEFAULT '';
