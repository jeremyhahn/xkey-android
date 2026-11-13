# Key sharing architecture

> **Status: REFERENCE** · Last verified: 2026-08-10 (desktop sharing section: 2026-11-12)
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
- The revocation is durable. The removed key goes into a pending set
  (`pending_grant_revocations` in the paired-devices prefs) in the same edit
  that removes the pairing, and leaves it only once the delete commits. A
  delete that failed or never ran is retried at the next app start and when
  the key is paired again. Until then `canShareKeyWithPeer` refuses
  `SELECTED_PEERS` to that key (fail closed).
- Re-pairing under the same key is not a removal, so with no revocation
  pending the rows stay.

## Index Strategy

### key_sharing_policies

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| (primary key) | `key_id, peer_public_key_hex` | Yes | Composite key for policy lookup |
| `index_key_sharing_policies_key_id` | `key_id` | No | All policies for a key |
| `index_key_sharing_policies_peer_public_key_hex` | `peer_public_key_hex` | No | All keys shared with a peer |

## Sending keys to the paired desktop

The sharing sheet (`ui/KeySharingBottomSheet.kt`) shows a **Paired desktop**
section while a desktop is connected. With no desktop the section is hidden
and the sheet works as before. The send goes through `DesktopKeyShare`
(`remote/RemoteShareClient.kt`), which asks `DesktopShareGate` first. Nothing
reaches the wire unless the gate allows it. The gate applies the rules the
phone applies to `local.importSharedKey`:

1. the session must carry a confirmed peer identity;
2. the key's recorded policy must admit that peer (`PRIVATE` never,
   `ALL_PEERS` always, `SELECTED_PEERS` only when `key_sharing_policies`
   lists it); a key with no record is not shareable;
3. a hardware (Keystore) key shares its public half only, via
   `remote.sharePublicKey`;
4. software key material is a candidate only when both the key store and the
   software key store mark it exportable and shareable.

The sheet shows the gate's answer: the send button for a public key, or the
reason nothing will be sent. Software key material is zeroed after the check
or the send.

### Why symmetric keys are not sent

`RemoteShareClient.shareSymmetric` implements `remote.shareSymmetric`, and it
zeroes the caller's key bytes and the encoded request after the send. The
sheet never offers it. At go-xkms xkey/v0.64.2-alpha the desktop bridge passes
`wrapped_key` to xkmsd's BYOK `ImportKey`, which expects key material wrapped
under the wrapping key and import token from `GetImportParameters`. The
pairing protocol has no method that gives the phone that key or token, so no
wrapping the phone can do matches what the desktop unwraps.
`DesktopShareGate.SYMMETRIC_WRAP_PATH_MATCHES` is false. An exportable
symmetric key gets the "cannot be sent yet" status, and only public keys are
sent.
