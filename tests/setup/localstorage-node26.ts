// Node 26 defines a global `localStorage` accessor that returns undefined
// without `--localstorage-file`, shadowing happy-dom's. Take it back.
// The `document` guard matters: node-env tests also see a global `Storage`,
// but Node's is an illegal constructor and throws during collection.
if (typeof document !== 'undefined' && globalThis.localStorage === undefined) {
    try {
        Object.defineProperty(globalThis, 'localStorage', {
            value: new Storage(),
            configurable: true,
            writable: true
        });
    } catch { /* leave it; the affected tests fail with their own error */ }
}

export {};
