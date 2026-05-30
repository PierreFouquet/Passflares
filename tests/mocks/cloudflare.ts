import { vi } from 'vitest';

// --- D1 mock ---

export type D1Response = {
    first?: Record<string, unknown> | null;
    all?: Record<string, unknown>[];
    run?: { success: boolean; last_row_id?: number };
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
                    meta: { last_row_id: response.run?.last_row_id ?? 1 },
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

// --- KV mock ---

export function createMockKV() {
    const store = new Map<string, string>();
    return {
        get: vi.fn((key: string) => Promise.resolve(store.get(key) ?? null)),
        put: vi.fn((key: string, value: string) => {
            store.set(key, value);
            return Promise.resolve();
        }),
        delete: vi.fn((key: string) => {
            store.delete(key);
            return Promise.resolve();
        }),
        _store: store
    } as unknown as KVNamespace;
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

// --- Env factory ---

export function createMockEnv(overrides: Partial<Record<string, unknown>> = {}) {
    return {
        DB: createMockDB(),
        VAULTS: createMockR2(),
        RATE_LIMIT: createMockKV(),
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
