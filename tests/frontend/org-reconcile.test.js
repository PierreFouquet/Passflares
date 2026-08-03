// @vitest-environment happy-dom
//
// reconcileOrgVaultKeys — the client half of organisation vault-key
// convergence (#69 residue).
//
// The defect it fixes: `shareOrgVaultsWithNewMember` ran exactly once, when a
// member was added. If the wrap was impossible at that instant — the member had
// never signed in, the admin could not open the vault, the request dropped —
// nothing ever went back to finish it. Members were permanently locked out of
// vaults they were entitled to, and no action available to anyone fixed it.
//
// So the properties under test are convergence properties: it must grant what it
// can, be safe to run repeatedly, never revoke, and never fail silently on the
// parts it cannot do.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const getOrgKeyGaps = vi.fn();
const apiGetVaults = vi.fn();
const decryptVaultContents = vi.fn();
const grantVaultKeyTo = vi.fn();
const putVaultKeyShares = vi.fn();

vi.mock('../../public/js/api.js', () => ({
    getOrgKeyGaps: (...a) => getOrgKeyGaps(...a),
    getVaults: (...a) => apiGetVaults(...a),
    getOrgMemberKeys: vi.fn(async () => ({ members: [] })),
    getUserPublicKey: vi.fn(async () => ({ publicKey: null })),
    putVaultKeyShares: (...a) => putVaultKeyShares(...a)
}));

vi.mock('../../public/js/vault-keys.js', () => ({
    decryptVaultContents: (...a) => decryptVaultContents(...a),
    grantVaultKeyTo: (...a) => grantVaultKeyTo(...a),
    rotateVaultKey: vi.fn(),
    orgIdOf: (v) => Number(String(v.owner_id).replace('org_', ''))
}));

let reconcileOrgVaultKeys;

const orgVault = (id, name) => ({
    id, name, owner_type: 'organization', owner_id: 'org_7', permission_level: 'manage'
});

beforeEach(async () => {
    vi.clearAllMocks();
    decryptVaultContents.mockResolvedValue({ entries: [], vaultKey: { fake: 'key' } });
    grantVaultKeyTo.mockResolvedValue(undefined);
    ({ reconcileOrgVaultKeys } = await import('../../public/js/org-keys.js'));
});

describe('reconcileOrgVaultKeys', () => {
    it('grants the key to every member missing it', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [{
                vaultId: 3, vaultName: 'Ops',
                missing: [
                    { userId: 5, email: 'a@x.co', publicKey: 'PUB_A' },
                    { userId: 6, email: 'b@x.co', publicKey: 'PUB_B' }
                ],
                notUpgraded: []
            }]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(2);
        expect(result.vaults).toBe(1);
        expect(grantVaultKeyTo).toHaveBeenCalledTimes(2);
        expect(grantVaultKeyTo).toHaveBeenCalledWith(3, { fake: 'key' }, expect.objectContaining({ userId: 5 }));
    });

    // The exact scenario that stranded people: invited before their first
    // sign-in, so there was no keypair to wrap to at add-member time.
    it('closes the gap for someone who has since signed in', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [{
                vaultId: 3, vaultName: 'Ops',
                missing: [{ userId: 5, email: 'late@x.co', publicKey: 'PUB_NOW_EXISTS' }],
                notUpgraded: []
            }]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(1);
        expect(result.notUpgraded).toEqual([]);
    });

    it('does nothing when there is nothing to do', async () => {
        getOrgKeyGaps.mockResolvedValue({ gaps: [] });

        const result = await reconcileOrgVaultKeys(7);

        expect(result).toEqual({ granted: 0, vaults: 0, unreachable: [], notUpgraded: [] });
        expect(grantVaultKeyTo).not.toHaveBeenCalled();
        // Must not even ask for the vault list when the server reports no gaps.
        expect(apiGetVaults).not.toHaveBeenCalled();
    });

    // Convergence means it can run on every page load. A second pass sees no
    // gaps, because the server recomputes them from what was actually written.
    it('is idempotent — a second run grants nothing', async () => {
        getOrgKeyGaps
            .mockResolvedValueOnce({
                gaps: [{ vaultId: 3, vaultName: 'Ops', missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }], notUpgraded: [] }]
            })
            .mockResolvedValueOnce({ gaps: [] });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        expect((await reconcileOrgVaultKeys(7)).granted).toBe(1);
        expect((await reconcileOrgVaultKeys(7)).granted).toBe(0);
    });

    // It adds shares; it must never replace the set. A reconcile that revoked
    // would be far worse than the bug it fixes.
    it('never rotates a key or replaces the share set', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [{ vaultId: 3, vaultName: 'Ops', missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }], notUpgraded: [] }]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        await reconcileOrgVaultKeys(7);

        expect(putVaultKeyShares).not.toHaveBeenCalledWith(
            expect.anything(), expect.anything(), expect.objectContaining({ replace: true })
        );
    });

    it('reports vaults it cannot open instead of failing the whole pass', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [
                { vaultId: 3, vaultName: 'Ops', missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }], notUpgraded: [] },
                { vaultId: 9, vaultName: 'Finance', missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }], notUpgraded: [] }
            ]
        });
        // Only Ops is in this user's vault list — Finance is not theirs to open.
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(1);
        expect(result.unreachable).toEqual(['Finance']);
    });

    it('reports a vault whose decryption fails, and still does the others', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [
                { vaultId: 3, vaultName: 'Ops', missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }], notUpgraded: [] },
                { vaultId: 9, vaultName: 'Finance', missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }], notUpgraded: [] }
            ]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops'), orgVault(9, 'Finance')]);
        decryptVaultContents.mockImplementation(async (v) => {
            if (v.id === 9) throw new Error('stale key');
            return { entries: [], vaultKey: { fake: 'key' } };
        });

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(1);
        expect(result.unreachable).toEqual(['Finance']);
    });

    it('passes through members who still have no keypair', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [{
                vaultId: 3, vaultName: 'Ops',
                missing: [{ userId: 5, email: 'a@x.co', publicKey: 'P' }],
                notUpgraded: [{ userId: 6, email: 'never@x.co' }]
            }]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(1);
        expect(result.notUpgraded).toEqual(['never@x.co']);
    });

    // One bad recipient must not block everyone queued behind them.
    it('keeps going when a single grant throws', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [{
                vaultId: 3, vaultName: 'Ops',
                missing: [
                    { userId: 5, email: 'bad@x.co', publicKey: 'CORRUPT' },
                    { userId: 6, email: 'good@x.co', publicKey: 'PUB_B' }
                ],
                notUpgraded: []
            }]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);
        grantVaultKeyTo.mockImplementation(async (_id, _key, member) => {
            if (member.userId === 5) throw new Error('bad public key');
        });

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(1);
        expect(result.notUpgraded).toContain('bad@x.co');
    });

    it('ignores a gap entry with no actionable members', async () => {
        getOrgKeyGaps.mockResolvedValue({
            gaps: [{ vaultId: 3, vaultName: 'Ops', missing: [], notUpgraded: [{ userId: 6, email: 'n@x.co' }] }]
        });
        apiGetVaults.mockResolvedValue([orgVault(3, 'Ops')]);

        const result = await reconcileOrgVaultKeys(7);

        expect(result.granted).toBe(0);
        expect(result.unreachable).toEqual([]);
        expect(result.notUpgraded).toEqual(['n@x.co']);
        expect(decryptVaultContents).not.toHaveBeenCalled();
    });
});
