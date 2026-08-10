#!/usr/bin/env node
// Falsifiability gate (#83): break a behaviour, prove a test notices.
//
// Usage: node scripts/mutation-check.mjs [--only <id>] [--suite <path>] [--targets <path>]
//
//   --only     run one mutant by id
//   --suite    run only the mutants whose suite is <path> (e.g. tests/frontend)
//   --targets  force every selected mutant to be judged by <path>, whatever
//              suite it declares. Debugging aid — narrowing the suite can only
//              turn a kill into a false SURVIVED, never the reverse.
//
// Each mutant declares the suite that is supposed to notice it (#89 §1). The
// backend was the whole sweep originally, which had it backwards for this
// product: the zero-knowledge guarantee lives in the browser, so a vacuous test
// over public/js/ hides more than a vacuous test over a handler.
//
// Exit 0 when every mutant is killed, 1 when any survives.

import { readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { mutants, DEFAULT_SUITE } from '../tests/mutation/mutants.mjs';

const args = process.argv.slice(2);
const flag = (name) => args.includes(name) ? args[args.indexOf(name) + 1] : null;
const only = flag('--only');
const suiteFilter = flag('--suite');
const targetsOverride = flag('--targets');

let selected = mutants;
if (only) selected = selected.filter(m => m.id === only);
if (suiteFilter) selected = selected.filter(m => (m.suite ?? DEFAULT_SUITE) === suiteFilter);

if (selected.length === 0) {
    const why = only ? `id "${only}"` : suiteFilter ? `suite "${suiteFilter}"` : 'any mutants';
    console.error(`No mutants matched ${why}.`);
    process.exit(1);
}

/** The suite that is supposed to notice this mutant. */
const suiteOf = (m) => targetsOverride ?? m.suite ?? DEFAULT_SUITE;

// A mutant is a deliberate vulnerability written into a real source file, and
// the `finally` below is what puts it back. That covers a normal run and not an
// interrupted one: Ctrl-C, a CI step timeout or a closed terminal all skip
// `finally`, leaving e.g. "sign-in sends the master password" sitting in the
// working tree for the next `git add -A` to commit. The sweep now takes ~13
// minutes, so being interrupted is an ordinary event rather than a freak one.
//
// Restoring on the way out needs the event loop to be free when the signal
// arrives, which is why the suite runs below are spawned asynchronously and
// awaited. With the original spawnSync the handler could not run until the
// child had already exited, so it never fired when it was actually needed —
// verified by killing a run mid-suite and finding the mutation still on disk.
let inFlight = null; // { file, original }

function restoreInFlight() {
    if (!inFlight) return;
    writeFileSync(inFlight.file, inFlight.original);
    inFlight = null;
}

let child = null;

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(signal, () => {
        const file = inFlight?.file;
        restoreInFlight();
        // The suite run is a grandchild via npx; leaving it behind would hold
        // the terminal and keep writing to a repo we have just restored.
        child?.kill('SIGKILL');
        console.error(`\nInterrupted (${signal})${file ? ` — restored ${file}` : ''}.`);
        process.exit(130);
    });
}
process.on('uncaughtException', (err) => {
    restoreInFlight();
    console.error(err);
    process.exit(1);
});
// Covers a process.exit() from anywhere else in this file. Not SIGKILL, which
// by definition cannot be handled — `git checkout -- src public/js` is the
// manual remedy, and `git status` shows it plainly.
process.on('exit', restoreInFlight);

/** Runs a suite. Resolves true when it passes (i.e. the mutant survived). */
function suitePasses(suite) {
    return new Promise((resolve) => {
        child = spawn('npx', ['vitest', 'run', suite], {
            stdio: ['ignore', 'ignore', 'ignore'],
            env: { ...process.env, CI: '1' }
        });
        child.on('close', (code) => { child = null; resolve(code === 0); });
        child.on('error', () => { child = null; resolve(false); });
    });
}

// Without this, a suite that is already red reports every mutant as "killed"
// and the gate passes while proving nothing. Checked once per distinct suite,
// before any mutation, so a red baseline is never mistaken for coverage.
const suites = [...new Set(selected.map(suiteOf))];
for (const suite of suites) {
    console.log(`Checking baseline (${suite})...`);
    if (!await suitePasses(suite)) {
        console.error(`Baseline suite ${suite} is FAILING. Fix it before running the gate — a\nred baseline kills every mutant for the wrong reason.`);
        process.exit(1);
    }
}

const survived = [];
const killed = [];
const regressed = [];

console.log(`Baseline green. Running ${selected.length} mutant(s) against ${suites.join(', ')}\n`);

// Widest id decides the column, so frontend ids (which are longer) don't shear
// the descriptions off into a ragged second column.
const pad = Math.max(...selected.map(m => m.id.length)) + 2;

for (const suite of suites) {
    const inSuite = selected.filter(m => suiteOf(m) === suite);
    if (suites.length > 1) console.log(`── ${suite} (${inSuite.length}) ${'─'.repeat(Math.max(0, 46 - suite.length))}`);

    for (const m of inSuite) {
        const original = readFileSync(m.file, 'utf8');
        const hits = original.split(m.find).length - 1;

        if (hits !== 1) {
            console.error(`✗ ${m.id}: pattern matched ${hits}× in ${m.file} (need exactly 1) — mutant is stale`);
            survived.push({ ...m, stale: true });
            continue;
        }

        try {
            inFlight = { file: m.file, original };
            writeFileSync(m.file, original.replace(m.find, m.replace));
            const passed = await suitePasses(suite);

            if (m.equivalent) {
                // Expected to survive: the mutated code is unreachable, so no
                // test can kill it. If one now does, the reasoning is stale —
                // re-triage.
                if (passed) {
                    console.log(`equivalent ${m.id.padEnd(pad - 1)}${m.equivalent}`);
                } else {
                    regressed.push(m);
                    console.log(`RE-TRIAGE ${m.id.padEnd(pad)}marked equivalent but a test killed it`);
                }
            } else if (passed) {
                survived.push(m);
                console.log(`SURVIVED  ${m.id.padEnd(pad)}${m.desc}`);
            } else {
                killed.push(m);
                console.log(`killed    ${m.id.padEnd(pad)}${m.desc}`);
            }
        } finally {
            restoreInFlight();
        }
    }

    if (suites.length > 1) console.log('');
}

const equivalents = selected.filter(m => m.equivalent).length;
console.log(`${killed.length} killed, ${survived.length} survived, ${equivalents} known-equivalent, ${selected.length} total`);

if (survived.length > 0) {
    console.log('\nSurviving mutants — the suite stayed green while these were broken:');
    for (const m of survived) {
        console.log(`  ${m.id} (${m.file})\n    ${m.stale ? 'STALE PATTERN — update tests/mutation/mutants.mjs' : m.desc}`);
    }
}
if (regressed.length > 0) {
    console.log('\nMutants marked equivalent that a test killed — remove the flag:');
    for (const m of regressed) console.log(`  ${m.id} (${m.file})`);
}

if (survived.length > 0 || regressed.length > 0) process.exit(1);

console.log('\nEvery falsifiable mutant was caught.');
