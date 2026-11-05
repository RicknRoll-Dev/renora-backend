# Renora backend

Go service that serves Renora's GraphQL API and runs its background jobs.

It implements the API contract in [`renora-api-contract`](https://github.com/RicknRoll-Dev/renora-api-contract):
the schema, the problem codes, the access rules and every behaviour of its stateful mock. The web app and
the mobile app are built against that mock, so they switch to this server by configuration alone. When a
rule is unclear, the mock's resolver (`mock/resolvers/`) and its tests (`test/flows.test.ts`,
`test/rules.test.ts`) are the reference.

One image, three binaries:

| Binary | Role | Ports |
|---|---|---|
| `api` | Public GraphQL API at `/graphql` | `8080` public, `9090` admin (`/metrics`, probes) |
| `worker` | River job queue: step clocks, notifications, AI calls | `9090` admin |
| `migrate` | Applies schema migrations; run as a release step before rollout | none |

## Run locally

Needs Go 1.26+, PostgreSQL 15+ and Redis 7+. To change the API you also need the contract checked out
beside this repo, as the apps expect it:

```
renora/                  this repo
renora-api-contract/     the contract
```

```sh
cp .env.example .env
make deps          # optional: Postgres 18 on :55432, Redis 8 on :56379 in Docker
make migrate-up
make api           # http://localhost:8080 (GraphQL playground at /)
make worker        # in another terminal; set ADMIN_ADDR=:9091 if the api uses :9090
```

To use a Postgres or Redis you already run, skip `make deps` and point `DATABASE_URL` and `REDIS_URL` in `.env` at them. Use a dedicated database (e.g. `renora`) and a Redis DB number that other projects don't use (e.g. `/1`).

`make help` lists every target.

## Layout

```
cmd/{api,worker,migrate}   entrypoints; wiring only
internal/api               router, admin router
internal/graph             resolvers, access rules (guard.go), GraphQL limits, error presenter
internal/graph/schema      the contract's schema, vendored by `make contract-sync`; never edited here
internal/graph/scalar      Money, Bps, DateTime, Date
internal/authn             who is calling: bearer token, session cookie, CSRF
internal/account           people and sign-in: phone codes, sessions, `me`
internal/ratelimit         fixed-window limits shared through Redis
internal/ids               prefixed ids (usr_…, ses_…) and secret tokens
internal/i18n              the request's language (Accept-Language) and bilingual text
internal/apperr            transport and auth errors (errors[].extensions.code)
internal/problem           domain problems, returned as data in result unions
internal/idempotency       idempotencyKey and clientRef, in the same transaction as the write
internal/config            env config with production safety checks
internal/platform/...      logging, telemetry, postgres, redis, queue, health, httpx
migrations                 goose SQL migrations, embedded in every binary
```

Domain modules (job, agreement, progress, handover, ...) go under `internal/<module>`.
Resolvers stay thin and call into them.

## Conventions

- **The schema is the contract's.** Change it by pull request in `renora-api-contract` (a review from backend
  and frontend), then `make contract-sync generate` here. `internal/graph/schema/CONTRACT_REF` records the
  contract commit. CI fails if the copy differs from the contract or generated code is stale.
- **Domain problems are data.** A mutation returns its result union: the payload, or `NotFound`, `Conflict`,
  `InvalidInput`, `QuotaReached` with a contract `ProblemCode`. Domain code returns a `*problem.Problem`; the
  resolver turns it into the union member with `problemResult`. A problem never travels as a GraphQL error.
- **Transport errors** use the contract's codes in `errors[].extensions.code`: `UNAUTHENTICATED`, `FORBIDDEN`,
  `CSRF_FAILED`, `RATE_LIMITED`, `BAD_USER_INPUT`, `INTERNAL` (`*apperr.Error`). Parse, validation, depth and
  complexity refusals and malformed scalars are `BAD_USER_INPUT`. Every other error is logged and masked as
  `INTERNAL`.
- **Access rules**, as the mock applies them: a root field without `@public` needs a session; a mutation on a
  cookie session needs `X-CSRF-Token` equal to the session's CSRF token; `@allow(roles:)` admits only those
  roles; `@private(to:)` reads `null` for everyone else, without an error.
- **Language.** Every string the server composes answers in the request's `Accept-Language` (`id` or `en`),
  else the signed-in user's language. Compose with `i18n.T(en, id)`, render with `.In(i18n.From(ctx))`.
- **Idempotency.** Mutations with `idempotencyKey` or `clientRef` run their writes in `idempotency.Do`, which
  claims the key, runs the write and stores the result in one transaction. Store small references (ids) and
  read current state from them.
- **Sign-in.** `requestCode` sends a 6-digit code (10 minutes, 5 wrong guesses, one resend per 30 s, 5 codes
  per number and 30 per address an hour); `verifyCode` starts a session of 30 days, no refresh. Web gets the
  httpOnly `renora_session` cookie plus `renora_csrf`; mobile gets a bearer token. Only hashes of codes and
  tokens are stored. A new number must pick `owner`, `contractor` or `supplier`; the code stays usable while it
  does. Ops sessions end after 30 minutes idle.
- **Ids** are a prefix and 16 Crockford base32 characters: `usr_7M2K9Q4XH1D8B3TW`.
- **Money** is `int64` whole rupiah, rates are `int` basis points. **DateTime** goes out in Asia/Jakarta with
  its offset (`2026-11-11T10:00:00+07:00`).
- **Database schemas.** Each Postgres schema has one owner. See [Database schemas](#database-schemas).
- **Migrations** are forward-only in production. Every migration needs a working `Down` for local use, and `TestUpDownUp` checks it.
- **Background work** is enqueued with River inside the same transaction as the data change it follows.
- **Time** is stored as `timestamptz` in UTC, and the connection time zone is pinned to UTC.

## Database schemas

The database is split into Postgres schemas by owner. Each schema is changed by exactly one migration system:

| Schema | Contents | Changed by |
|---|---|---|
| `public` | `goose_db_version` only: which app migrations have run | goose (`migrate up`) |
| `app` | Renora's own tables: users, jobs, agreements, ... | this repo's `migrations/` |
| `river` | Job queue tables (`river_job`, `river_leader`, ...) | River's migrator, run by `migrate up` |

Why not put everything in `public`:

1. **No name clashes.** River names its tables generically (`river_job`, `river_queue`); a library added later
   brings its own. In one shared namespace, Renora's names and theirs could collide.
2. **Clear ownership.** River's tables never appear in this repo's migrations, and River's migrator never touches
   `app`. When a table changes, its schema shows who changed it.
3. **Tighter permissions.** Roles can be granted per schema, e.g. a read-only reporting role on `app` alone.
4. **Easier operations.** Back up, restore or reset one part by schema name, e.g. `pg_dump -n app`.

Schemas cost nothing at query time. Queries name the schema explicitly (`app.jobs`), so nothing depends on `search_path`.

## Production settings

| Variable | Notes |
|---|---|
| `APP_ENV=production` | Introspection and playground default off. The playground cannot be turned on, and a `*` CORS origin is rejected at startup. |
| `HTTP_TRUSTED_PROXY_HOPS` | Number of proxies that append to `X-Forwarded-For`, e.g. `1` behind one load balancer. Leave at `0` when there is no proxy. |
| `HTTP_SHUTDOWN_DELAY` | How long `/readyz` reports draining before connections close. Set it to about your load balancer's probe interval, e.g. `10s`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns on trace export. `OTEL_TRACES_SAMPLER_ARG` sets the sampling ratio. |
| `GRAPHQL_COMPLEXITY_LIMIT`, `GRAPHQL_DEPTH_LIMIT` | Query cost limits. |
| `AUTH_SECRET` | Required: at least 32 random bytes. Keys the stored hashes of sign-in codes. |
| `AUTH_CODE_SENDER` | How codes reach phones. Only `log` exists, and production refuses it, so **production cannot start until a WhatsApp/SMS provider is wired**. |
| `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_DOMAIN` | Secure must stay on. Set the domain only when the web app and the API are on different subdomains of one site. |
| `CORS_ALLOWED_ORIGINS` | The web app's origins. Credentials are allowed (the session cookie), so never `*`. The same list gates WebSocket origins. Serving the API on the app's own origin (`/graphql` behind the same host) avoids CORS altogether, as the web app recommends. |

**Subscriptions** run over graphql-ws at `/graphql` (subprotocols `graphql-transport-ws` and `graphql-ws`). A
load balancer in front must allow WebSocket upgrades and idle connections of at least a minute; the server
pings every 25 s.

**CI** needs the secret `CONTRACT_DEPLOY_KEY`, a read-only deploy key on `renora-api-contract` (the same one the
apps use), for the job that checks the vendored schema.

Alert when `time() - max(queue_heartbeat_last_success_timestamp_seconds) > 300`: no worker is processing jobs.
