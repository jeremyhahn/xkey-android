# Key sharing architecture

> **Status: REFERENCE** · Last verified: 2026-08-10
> As-built description of the xKey Room schema. STALE: the migration table stops at v7; `XKeyDatabase.kt` is at version 11. Read the code for v8-v11.

## Entity Details

### KeySharingPolicy (`key_sharing_policies`)

Per-key, per-peer sharing rules. Only consulted when `KeyEntity.sharingPolicy`
is `SELECTED_PEERS`. Uses a composite primary key of `(key_id, peer_public_key_hex)`.

**Row lifetime.** A row lives no longer than both its key and its peer's
pairing:

- Deleting the key deletes its rows (foreign key onto `keys`, `ON DELETE CASCADE`).
- A peer that stops being paired loses all its rows (#174). Every removal path
  of `PairedDeviceRepository` (`removeDevice`, the eviction of a stale entry
  when a device re-pairs under a new key, and `clear()`) tells its removal
  listeners. `PairedDeviceGrantCleanup`, registered in `XKeyApplication`, then
  runs `KeySharingPolicyDao.clearPoliciesForPeer` on an IO coroutine. When it
  deletes rows, it audits the count as `KEY_SHARING_CHANGED` with details
  `reason=peer_unpaired`, `droppedGrants=<n>`. A desktop that re-pairs under
  the same static key therefore starts with no `SELECTED_PEERS` grants. It
  still reaches `ALL_PEERS` keys, because that comes from the key's own policy,
  not from a row.
- Re-pairing under the same key is not a removal, so the rows stay.

## Index Strategy

### key_sharing_policies

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| (primary key) | `key_id, peer_public_key_hex` | Yes | Composite key for policy lookup |
| `index_key_sharing_policies_key_id` | `key_id` | No | All policies for a key |
| `index_key_sharing_policies_peer_public_key_hex` | `peer_public_key_hex` | No | All keys shared with a peer |
