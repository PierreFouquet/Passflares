// Stand-in for the `cloudflare:workers` built-in module.
//
// The backend suite runs in plain Node (vitest `environment: 'node'`), not
// workerd, so the runtime module doesn't resolve. vitest.config.ts aliases
// `cloudflare:workers` here, which lets src/rateLimiter.ts be imported and
// exercised directly — the DurableObject base class contributes nothing but
// `this.ctx` / `this.env` wiring.
//
// The real behaviour under test is in RateLimiter's own methods, and the
// serialisation guarantee it depends on is provided by the platform. See
// tests/backend/rate-limiter.test.ts for how concurrency is simulated.

export class DurableObject<Env = unknown> {
    readonly ctx: DurableObjectState;
    readonly env: Env;

    constructor(ctx: DurableObjectState, env: Env) {
        this.ctx = ctx;
        this.env = env;
    }
}

export class WorkerEntrypoint<Env = unknown> {
    readonly ctx: ExecutionContext;
    readonly env: Env;

    constructor(ctx: ExecutionContext, env: Env) {
        this.ctx = ctx;
        this.env = env;
    }
}

export class RpcTarget {}
