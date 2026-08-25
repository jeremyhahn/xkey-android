/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.protocol

/**
 * The facts about the live Noise session that
 * [AttestTranscript.channelBinding] is derived from.
 *
 * Roles are named rather than inferred because only the transport knows them.
 * A [com.automatethethings.xkey.ble.NoiseSession] tracks "local" and "remote"
 * static keys and has no idea which end opened the handshake; the same class
 * serves as the responder under `StreamPairingSession` and `GattServer` and as
 * the *initiator* under `BleClient`. Deriving initiator/responder from local and
 * remote inside the session would therefore be right in one place and silently
 * wrong in another, and the failure would be a signature that never verifies.
 *
 * @property initiatorStaticPublicKey the xkey desktop's 32-byte Noise static
 *   public key — the peer, on every path that answers `local.attestDevice`.
 * @property responderStaticPublicKey this phone's 32-byte Noise static public key.
 * @property prologue the prologue the handshake actually ran under: 32 bytes on a
 *   reconnect that bound a known fingerprint, empty on a first pairing.
 */
class SessionBinding(
    val initiatorStaticPublicKey: ByteArray,
    val responderStaticPublicKey: ByteArray,
    val prologue: ByteArray,
)

/**
 * Supplies the live [SessionBinding], or null when there is no established
 * session to bind to.
 *
 * The handler holds a provider rather than a snapshot so the binding is read at
 * the moment the transcript is built. A value captured earlier could outlive its
 * connection and bind an attestation to a session that has already gone.
 */
fun interface SessionBindingProvider {
    fun binding(): SessionBinding?
}
