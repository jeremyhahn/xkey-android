# Key sharing architecture

> Status: reference. Last checked against main on 2026-11-23.
> This page describes how a key's sharing policy is stored and enforced, and how
> the phone sends keys to a paired desktop. The full Room schema (version 13) is
> in [hardware-backed keys](../hardware-backed-keys/architecture.md#data-model).

## Sharing policy

Each row in the `keys` table (`KeyEntity`) has a `sharingPolicy`:

- `PRIVATE`: the key is never shared.
- `ALL_PEERS`: any paired peer with a confirmed identity may receive it.
- `SELECTED_PEERS`: only peers listed in `key_sharing_policies` may receive it.

`local.importSharedKey` in `protocol/Handler.kt` checks this policy through
`authorizeShare` and `canShareKeyWithPeer` before it returns anything. The
check needs a confirmed peer identity for the session.

### KeySharingPolicy (`key_sharing_policies`)

Per-key, per-peer grants. They are read only when `KeyEntity.sharingPolicy` is
`SELECTED_PEERS`. The primary key is the pair `(key_id, peer_public_key_hex)`.

A row lives no longer than both its key and its peer's pairing:

- Deleting the key deletes its rows (foreign key onto `keys`, `ON DELETE CASCADE`).
- A peer that stops being paired loses all its rows (#174). Every removal path
  of `PairedDeviceRepository` (`removeDevice`, the eviction of a stale entry
  when a device re-pairs under a new key, and `clear()`) tells its removal
  listeners. `PairedDeviceGrantCleanup`, registered in `XKeyApplication`, then
  runs `KeySharingPolicyDao.clearPoliciesForPeer` on an IO coroutine. When it
  deletes rows, `AuditLogger.logPeerGrantsDropped` records the count as
  `KEY_SHARING_CHANGED` with details `reason=peer_unpaired` and
  `droppedGrants=<n>`. A desktop that re-pairs under the same static key
  therefore starts with no `SELECTED_PEERS` grants. It still reaches
  `ALL_PEERS` keys, because that comes from the key's own policy and not from
  a row.
- The revocation is durable. The removed key goes into a pending set
  (`pending_grant_revocations` in the paired-devices prefs) in the same edit
  that removes the pairing, and leaves it only once the delete commits. A
  delete that failed or never ran is retried at the next app start and when
  the key is paired again. Until then `canShareKeyWithPeer` refuses
  `SELECTED_PEERS` to that key, so the check fails closed.
- Re-pairing under the same key is not a removal, so with no revocation
  pending the rows stay.

| Index | Columns | Unique | Purpose |
|-------|---------|--------|---------|
| (primary key) | `key_id, peer_public_key_hex` | Yes | Policy lookup |
| `index_key_sharing_policies_key_id` | `key_id` | No | All grants for a key |
| `index_key_sharing_policies_peer_public_key_hex` | `peer_public_key_hex` | No | All keys granted to a peer |

### Audit

Every transfer is audited with the peer's device id and name and no key bytes
(#222). `local.importSharedKey` records `KEY_EXPORTED` with format `raw`,
`metadata` or `public`, and a policy refusal as a failed entry.
`local.shareSymmetric` records `KEY_CREATED`, and `local.sharePublicKey`
records `CONTACT_IMPORTED` with source `shared`. See
[the audit log architecture](../audit-log/architecture.md).

## Sending keys to the paired desktop

The sharing sheet (`ui/KeySharingBottomSheet.kt`) shows a "Paired desktop"
section while a desktop is connected. With no desktop the section is hidden.
The send goes through `DesktopKeyShare` in `remote/RemoteShareClient.kt`,
which asks `DesktopShareGate.decide` first. Nothing reaches the wire unless
the gate allows it. The gate applies the rules the phone applies to
`local.importSharedKey`, plus one more:

1. The session must carry a confirmed peer identity.
2. The key's recorded policy must admit that peer: `PRIVATE` never,
   `ALL_PEERS` always, `SELECTED_PEERS` only when `key_sharing_policies` lists
   it and no unpair revocation is pending for the peer. A key with no record
   is not shareable.
3. The phone's own identity keys (the `DeviceIdentity` enrollment keys and the
   user verification key) and the ephemeral agreement keys of
   `FileEncryptor` are never shared. `local.importSharedKey` has no such
   exclusion.
4. A hardware (Keystore) key shares its public half only, through
   `remote.sharePublicKey`.
5. Software key material is a candidate only when both the key table and the
   software key store mark it exportable and shareable.

The sheet shows the gate's answer: the send button for a public key, or the
reason nothing will be sent (the `sharing_desktop_*` strings in
`res/values/strings_sharing.xml`). Software key material is zeroed after the
check or the send.

`SharePermissionLedger` closes the race between a send and a revoke. A share
takes a revision of the key before it enters the transport, and the transport
checks that revision when it admits the send. Every writer that narrows what a
key may be shared with (its policy, a peer grant, or deleting the key) runs
through `SharePermissionLedger.revoking`. A revoke that started before
admission refuses the send, and one that starts after admission is ordered
after it.

### Why symmetric keys are not sent

`RemoteShareClient.shareSymmetric` implements `remote.shareSymmetric`. It
zeroes the caller's key bytes and the encoded request after the send, but the
sheet never offers it. At go-xkms xkey/v0.64.2-alpha the desktop bridge passes
`wrapped_key` to xkmsd's BYOK `ImportKey`, which expects key material wrapped
under the wrapping key and import token from `GetImportParameters`. The
pairing protocol has no method that gives the phone that key or token, so no
wrapping the phone can do matches what the desktop unwraps.
`DesktopShareGate.SYMMETRIC_WRAP_PATH_MATCHES` is false. An exportable
symmetric key gets the "cannot be sent to the desktop yet" status, and only
public keys are sent.

## Related features

- [Exportable symmetric keys](../exportable-symmetric-keys/architecture.md):
  the software keys whose material `local.importSharedKey` can return.
- [Noise pairing](../noise-pairing/architecture.md): the confirmed peer
  identity the checks rely on.
