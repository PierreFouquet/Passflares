// @vitest-environment happy-dom
import { describe, it, expect } from 'vitest';
import { computeSecurityOverview } from '../../../public/js/pages/dashboard.js';

describe('computeSecurityOverview', () => {
    it('returns zeros for empty entries', () => {
        const r = computeSecurityOverview([]);
        expect(r.total).toBe(0);
        expect(r.weak).toBe(0);
        expect(r.reused).toBe(0);
    });

    it('counts total entries across vaults', () => {
        const entries = [
            { entry: { name: 'a', password: 'StrongP@ss12345' } },
            { entry: { name: 'b', password: 'AnotherStrongPW#9' } }
        ];
        const r = computeSecurityOverview(entries);
        expect(r.total).toBe(2);
    });

    it('counts weak passwords (score < 3)', () => {
        const entries = [
            { entry: { name: 'a', password: 'abc' } },          // weak
            { entry: { name: 'b', password: '12345' } },        // weak
            { entry: { name: 'c', password: 'AStrong!12345' } } // strong
        ];
        const r = computeSecurityOverview(entries);
        expect(r.weak).toBe(2);
    });

    it('counts reused passwords (used in >1 entry)', () => {
        const entries = [
            { entry: { name: 'a', password: 'samepw' } },
            { entry: { name: 'b', password: 'samepw' } },
            { entry: { name: 'c', password: 'unique' } }
        ];
        const r = computeSecurityOverview(entries);
        // Two entries share the password → both flagged as reused
        expect(r.reused).toBe(2);
    });

    it('does not flag unique passwords as reused', () => {
        const entries = [
            { entry: { name: 'a', password: 'pwA' } },
            { entry: { name: 'b', password: 'pwB' } }
        ];
        const r = computeSecurityOverview(entries);
        expect(r.reused).toBe(0);
    });

    it('ignores entries with no password set', () => {
        const entries = [
            { entry: { name: 'a' } },
            { entry: { name: 'b', password: '' } },
            { entry: { name: 'c', password: 'pw' } }
        ];
        const r = computeSecurityOverview(entries);
        // Only `c` has a non-empty password → weak count 1, total 3
        expect(r.weak).toBe(1);
        expect(r.total).toBe(3);
    });
});
