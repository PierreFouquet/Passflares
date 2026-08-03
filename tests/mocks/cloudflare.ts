import { vi } from 'vitest';
import { RateLimiter } from '../../src/rateLimiter.js';

// --- D1 mock ---

export type D1Response = {
    first?: Record<string, unknown> | null;
    all?: Record<string, unknown>[];
    // `changes` matters for any statement whose *result count* decides the
    // outcome — the guarded recovery-code UPDATE in src/totp.ts reads it to
    // decide whether it claimed the code (GHSA-q9vh-jccv-9p23).
    run?: { success: boolean; last_row_id?: number; changes?: number };
};

function makeStatement(response: D1Response) {
    return {
        bind: vi.fn(() => ({
            first: vi.fn(() => Promise.resolve(response.first ?? null)),
            all: vi.fn(() =>
                Promise.resolve({ results: response.all ?? [], success: true })
            ),
            run: vi.fn(() =>
                Promise.resolve({
                    success: response.run?.success ?? true,
                    meta: {
                        last_row_id: response.run?.last_row_id ?? 1,
                        changes: response.run?.changes ?? 0
                    },
                    results: []
                })
            )
        }))
    };
}

/**
 * Creates a mock D1Database.
 * Pass a map of SQL substrings → D1Response so `prepare()` returns the
 * right mock based on which table/verb is in the query.
 */
export function createMockDB(responses: Record<string, D1Response> = {}) {
    return {
        prepare: vi.fn((sql: string) => {
            const key = Object.keys(responses).find(k => sql.includes(k));
            return makeStatement(key ? responses[key] : {});
        }),
        exec: vi.fn(() => Promise.resolve({ results: [], success: true })),
        batch: vi.fn(() => Promise.resolve([]))
    } as unknown as D1Database;
}

// --- R2 mock ---

export function createMockR2() {
    const store = new Map<string, string>();
    return {
        get: vi.fn((key: string) => {
            const val = store.get(key);
            if (!val) return Promise.resolve(null);
            return Promise.resolve({ json: () => Promise.resolve(JSON.parse(val)) });
        }),
        put: vi.fn((key: string, value: string) => {
            store.set(key, value);
            return Promise.resolve();
        }),
        delete: vi.fn((key: string) => {
            store.delete(key);
            return Promise.resolve();
        }),
        _store: store
    } as unknown as R2Bucket;
}

// --- Durable Object mock ---

/**
 * Minimal DurableObjectState backed by a Map.
 *
 * Deliberately *not* a fake of the limiter's logic — it stores what the real
 * one stores, so `RateLimiter` runs unmodified against it.
 */
export function createMockDurableObjectState() {
    const store = new Map<string, unknown>();
    let alarm: number | null = null;
    return {
        storage: {
            get: vi.fn(async (key: string) => store.get(key)),
            put: vi.fn(async (key: string, value: unknown) => { store.set(key, value); }),
            delete: vi.fn(async (key: string) => store.delete(key)),
            deleteAll: vi.fn(async () => { store.clear(); }),
            setAlarm: vi.fn(async (time: number) => { alarm = time; }),
            getAlarm: vi.fn(async () => alarm),
            deleteAlarm: vi.fn(async () => { alarm = null; })
        },
        blockConcurrencyWhile: vi.fn(async (fn: () => Promise<unknown>) => fn()),
        _store: store,
        _alarm: () => alarm
    } as unknown as DurableObjectState & { _store: Map<string, unknown>; _alarm: () => number | null };
}

/**
 * Wraps a Durable Object instance so its async methods run one at a time.
 *
 * This models workerd's *input gates*: while a storage operation is in flight,
 * the runtime delivers no other events to that object. That guarantee is the
 * reason `RateLimiter.fail()` can do a plain read-modify-write without locking,
 * and it is what KV structurally could not offer (GHSA-vp89-22wm-gjr8).
 *
 * Without this, the mock would interleave awaits and reproduce the very bug the
 * fix removes — making tests fail for a reason the platform does not have.
 */
function withInputGate<T extends object>(instance: T): T {
    let queue: Promise<unknown> = Promise.resolve();
    return new Proxy(instance, {
        get(target, prop, receiver) {
            const value = Reflect.get(target, prop, receiver);
            if (typeof value !== 'function') return value;
            return (...args: unknown[]) => {
                const run = queue.then(() => (value as Function).apply(target, args));
                // Keep the chain alive even if one call rejects.
                queue = run.then(() => undefined, () => undefined);
                return run;
            };
        }
    });
}

/**
 * A DurableObjectNamespace that instantiates the real class, one instance per
 * name — mirroring `idFromName`, where the same name always resolves to the
 * same object and different names never share state.
 */
export function createMockDurableObjectNamespace<T extends object>(
    factory: (state: DurableObjectState, env: unknown) => T,
    env: unknown = {}
) {
    const instances = new Map<string, T>();
    const states = new Map<string, ReturnType<typeof createMockDurableObjectState>>();

    const instanceFor = (name: string): T => {
        if (!instances.has(name)) {
            const state = createMockDurableObjectState();
            states.set(name, state);
            instances.set(name, withInputGate(factory(state, env)));
        }
        return instances.get(name)!;
    };

    return {
        // The mock treats the name itself as the ID; the real hash is opaque and
        // irrelevant, only the name → instance mapping matters here.
        idFromName: vi.fn((name: string) => name),
        idFromString: vi.fn((id: string) => id),
        newUniqueId: vi.fn(() => `unique-${Math.random()}`),
        get: vi.fn((id: string) => instanceFor(id)),
        getByName: vi.fn((name: string) => instanceFor(name)),
        _instances: instances,
        _states: states
    } as unknown as DurableObjectNamespace<any> & {
        _instances: Map<string, T>;
        _states: Map<string, ReturnType<typeof createMockDurableObjectState>>;
    };
}

/** A namespace wired to the real RateLimiter, for handler-level tests. */
export function createMockRateLimiter() {
    return createMockDurableObjectNamespace(
        (state, env) => new RateLimiter(state, env as any)
    );
}

// --- Env factory ---

export function createMockEnv(overrides: Partial<Record<string, unknown>> = {}) {
    return {
        DB: createMockDB(),
        VAULTS: createMockR2(),
        RATE_LIMITER: createMockRateLimiter(),
        ASSETS: {} as Fetcher,
        JWT_SECRET: 'test-jwt-secret-32-chars-minimum!!',
        TURNSTILE_KEY: 'test-turnstile-key',
        TOTP_ENC_KEY: 'test-totp-enc-key-32-chars-minimum!!',
        ...overrides
    };
}

// --- Request helpers ---

export function makeRequest(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {}
): Request {
    return new Request(`https://passflares.test${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        body: body ? JSON.stringify(body) : undefined
    }) as unknown as Request;
}

export function makeAuthRequest(
    method: string,
    path: string,
    token: string,
    body?: unknown,
    params?: Record<string, string>
) {
    const req = makeRequest(method, path, body, {
        Authorization: `Bearer ${token}`
    }) as any;
    req.params = params ?? {};
    req.user = undefined;
    return req;
}

export const mockCtx: ExecutionContext = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn()
} as unknown as ExecutionContext;
