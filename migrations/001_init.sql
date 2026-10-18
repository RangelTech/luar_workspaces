-- runtime-manager schema. Desired state lives here; observed state lives in Docker labels rt.*.
CREATE TABLE IF NOT EXISTS tenant_runtime (
    tenant_id              text PRIMARY KEY,
    plan                   text NOT NULL DEFAULT 'standard',
    desired_state          text NOT NULL DEFAULT 'running',  -- running|stopped|retired|destroyed
    runtime_enabled        boolean NOT NULL DEFAULT false,
    workspace_enabled      boolean NOT NULL DEFAULT true,
    runtime_desired        text NOT NULL DEFAULT 'running',  -- running|stopped
    workspace_desired      text NOT NULL DEFAULT 'running',
    runtime_image_digest   text NOT NULL DEFAULT '',
    workspace_image_digest text NOT NULL DEFAULT '',
    limits_json            jsonb NOT NULL DEFAULT '{}'::jsonb,
    quota_gb               integer NOT NULL DEFAULT 10,
    exposures              jsonb NOT NULL DEFAULT '[]'::jsonb,
    generation             integer NOT NULL DEFAULT 1,
    suspended              boolean NOT NULL DEFAULT false,
    suspend_reason         text NOT NULL DEFAULT '',
    suspended_by           text NOT NULL DEFAULT '',
    status                 text NOT NULL DEFAULT 'provisioning',
    last_activity_at       timestamptz,
    last_error             text NOT NULL DEFAULT '',
    net_index              integer NOT NULL UNIQUE,
    authorized_key         text NOT NULL DEFAULT '',
    purge_after            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE SEQUENCE IF NOT EXISTS tenant_net_index_seq MINVALUE 0 START 0;

CREATE TABLE IF NOT EXISTS tenant_runtime_event (
    id          bigserial PRIMARY KEY,
    tenant_id   text NOT NULL,
    ts          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,
    action      text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   text NOT NULL,
    hash        text NOT NULL
);
CREATE INDEX IF NOT EXISTS tenant_runtime_event_tenant ON tenant_runtime_event (tenant_id, id DESC);

CREATE TABLE IF NOT EXISTS rm_idempotency (
    tenant_id    text NOT NULL,
    idem_key     text NOT NULL,
    request_hash text NOT NULL,
    response     jsonb NOT NULL,
    status_code  integer NOT NULL DEFAULT 200,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idem_key)
);

CREATE TABLE IF NOT EXISTS pool_worker (
    worker_id        text PRIMARY KEY,
    slot             integer NOT NULL UNIQUE,
    status           text NOT NULL DEFAULT 'pending',  -- pending|ready|fencing|fenced|recycling|failed
    image_digest     text NOT NULL DEFAULT '',
    generation       integer NOT NULL DEFAULT 1,
    runs_served      integer NOT NULL DEFAULT 0,
    inflight         integer NOT NULL DEFAULT 0,
    recycle_due      boolean NOT NULL DEFAULT false,
    last_error       text NOT NULL DEFAULT '',
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rm_kv (
    k text PRIMARY KEY,
    v jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_usage_hourly (
    tenant_id         text NOT NULL,
    hour              timestamptz NOT NULL,
    cpu_seconds       double precision NOT NULL DEFAULT 0,
    mem_gb_hours      double precision NOT NULL DEFAULT 0,
    ws_uptime_h       double precision NOT NULL DEFAULT 0,
    runtime_uptime_h  double precision NOT NULL DEFAULT 0,
    disk_gb           double precision NOT NULL DEFAULT 0,
    egress_gb         double precision NOT NULL DEFAULT 0,
    runs              integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, hour)
);

CREATE TABLE IF NOT EXISTS tenant_backup (
    backup_id   text PRIMARY KEY,
    tenant_id   text NOT NULL,
    kind        text NOT NULL,
    location    text NOT NULL,
    sha256      text NOT NULL DEFAULT '',
    manifest    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_domain (
    host        text PRIMARY KEY,
    tenant_id   text NOT NULL,
    app         text NOT NULL,
    token       text NOT NULL,
    verified    boolean NOT NULL DEFAULT false,
    active      boolean NOT NULL DEFAULT false,
    last_check_at timestamptz,
    verified_at timestamptz
);
