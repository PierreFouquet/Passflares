#!/usr/bin/env node
// Falsifiability gate (#83): break a behaviour, prove a test notices.
//
// Usage: node scripts/mutation-check.mjs [--only <id>] [--targets <path>]
//
// Exit 0 when every mutant is killed, 1 when any survives.

import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { mutants } from '../tests/mutation/mutants.mjs';

const args = process.argv.slice(2);
const only = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;
const targets = args.includes('--targets') ? args[args.indexOf('--targets') + 1] : 'tests/backend';

const selected = only ? mutants.filter(m => m.id === only) : mutants;
if (selected.length === 0) {
    console.error(only ? `No mutant with id "${only}".` : 'No mutants defined.');
    process.exit(1);
}

/** Runs the suite. Returns true when it passes (i.e. the mutant survived). */
function suitePasses() {
    const res = spawnSync('npx', ['vitest', 'run', targets], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, CI: '1' }
    });
    return res.status === 0;
}

// Without this, a suite that is already red reports every mutant as "killed"
// and the gate passes while proving nothing.
console.log(`Checking baseline (${targets})...`);
if (!suitePasses()) {
    console.error('Baseline suite is FAILING. Fix it before running the gate — a red\nbaseline kills every mutant for the wrong reason.');
    process.exit(1);
}

const survived = [];
const killed = [];
const regressed = [];

console.log(`Baseline green. Running ${selected.length} mutant(s) against ${targets}\n`);

for (const m of selected) {
    const original = readFileSync(m.file, 'utf8');
    const hits = original.split(m.find).length - 1;

    if (hits !== 1) {
        console.error(`✗ ${m.id}: pattern matched ${hits}× in ${m.file} (need exactly 1) — mutant is stale`);
        survived.push({ ...m, stale: true });
        continue;
    }

    try {
        writeFileSync(m.file, original.replace(m.find, m.replace));
        const passed = suitePasses();

        if (m.equivalent) {
            // Expected to survive: the mutated code is unreachable, so no test
            // can kill it. If one now does, the reasoning is stale — re-triage.
            if (passed) {
                console.log(`equivalent ${m.id.padEnd(27)} ${m.equivalent}`);
            } else {
                regressed.push(m);
                console.log(`RE-TRIAGE ${m.id.padEnd(28)} marked equivalent but a test killed it`);
            }
        } else if (passed) {
            survived.push(m);
            console.log(`SURVIVED  ${m.id.padEnd(28)} ${m.desc}`);
        } else {
            killed.push(m);
            console.log(`killed    ${m.id.padEnd(28)} ${m.desc}`);
        }
    } finally {
        writeFileSync(m.file, original);
    }
}

const equivalents = selected.filter(m => m.equivalent).length;
console.log(`\n${killed.length} killed, ${survived.length} survived, ${equivalents} known-equivalent, ${selected.length} total`);

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
