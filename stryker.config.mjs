// Generated mutation testing over src/ (#89 §2, #83 §A).
//
// Complements the curated gate rather than replacing it. The two answer
// different questions:
//
//   scripts/mutation-check.mjs  — "do the behaviours we care about have tests
//                                 that fail when they break?" 46 hand-written
//                                 mutants, ~13 min, runs on every PR.
//   Stryker (this file)         — "what did nobody think to break?" Hundreds of
//                                 generated mutants, far slower, run on demand.
//
// Generation finds the mutants nobody thought of; curation keeps the fast CI
// signal readable and its failures actionable. Deleting either loses something.
//
// Run: npm run test:stryker  (or `-- --mutate src/middleware.ts` for one file)
export default {
    testRunner: 'vitest',

    // Points at a file that deliberately does not exist, which is the only way
    // to stop Stryker preprocessing our real tsconfig.json.
    //
    // This project is on TypeScript 7 — the native port, whose JS API exports
    // two symbols rather than the classic compiler surface. Stryker's
    // TSConfigPreprocessor calls ts.parseConfigFileTextToJson, which no longer
    // exists, and the run dies with "ts.parseConfigFileTextToJson is not a
    // function" before a single mutant is created. Naming a tsconfig that is
    // absent makes the preprocessor a no-op.
    //
    // Nothing is lost: the preprocessor only rewrites tsconfig `extends`/
    // `references` paths for the sandbox copy, and this repo has a single flat
    // tsconfig with neither. Revisit when Stryker supports TS 7.
    tsconfigFile: 'stryker-no-tsconfig.json',
    vitest: {
        // Backend-only, no coverage — see vitest.stryker.mts for why.
        configFile: 'vitest.stryker.mts'
    },

    // src/ only. public/js/ is covered by the curated gate's frontend sweep;
    // Stryker would need a second runner profile for happy-dom, and the browser
    // mutants that matter are the hand-written ones anyway.
    mutate: [
        'src/**/*.ts',
        // Type-only and constant modules: mutating them produces mutants that
        // either do not compile or change nothing observable.
        '!src/types.d.ts'
    ],

    // Runs only the tests that covered the mutated line, which is the
    // difference between a run measured in minutes and one measured in hours.
    //
    // IMPORTANT — a SURVIVOR HERE IS A LEAD, NOT A FINDING. perTest selection
    // under-approximates on this project: of the first five survivors checked
    // by hand, three were killed outright by the full backend suite. Reproduce
    // before writing anything:
    //
    //   1. apply the mutation to the source by hand
    //   2. npx vitest run tests/backend
    //   3. if it goes red, the mutant was a false survivor — discard it
    //   4. if it stays green, the gap is real: add a test, then add the mutant
    //      to tests/mutation/mutants.mjs so the gate holds it permanently
    //
    // That is how turnstile-secret-blanked and turnstile-ignores-http-status
    // got there. Setting this to 'all' removes the false positives and makes
    // the run roughly twenty times longer; for an on-demand tool the cheap run
    // plus a manual confirmation step is the better trade.
    coverageAnalysis: 'perTest',

    reporters: ['progress', 'clear-text', 'json'],
    jsonReporter: { fileName: 'reports/mutation/mutation.json' },
    htmlReporter: { fileName: 'reports/mutation/index.html' },

    // Thresholds are advisory here, not a gate: `break: null` means Stryker
    // never fails the command on score alone. The per-PR gate is the curated
    // one; this is an exploration tool, and a hard threshold on a generated
    // score invites the worst possible fix — deleting inconvenient mutants.
    thresholds: { high: 85, low: 70, break: null },

    // A mutant that makes a test hang (an inverted loop condition, say) would
    // otherwise stall the run until the default timeout on every such mutant.
    timeoutMS: 20000,
    timeoutFactor: 2,

    concurrency: 4,
    tempDirName: '.stryker-tmp',
    cleanTempDir: true
};
