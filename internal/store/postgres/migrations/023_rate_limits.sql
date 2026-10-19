-- Fixed-window request counters shared by all replicas (auth.rate_limit_shared).
CREATE TABLE rate_limits (
    key          text        NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL,
    PRIMARY KEY (key, window_start)
);
