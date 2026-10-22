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

package com.automatethethings.xkey.ble

import com.automatethethings.xkey.protocol.SessionBinding

/**
 * The static keys and prologue `local.attestDevice` binds its attestation to
 * (go-xkms#129 §5), and the pairing SAS is derived from, for a session where
 * this phone is the Noise **responder** — GATT server, TCP, USB. The desktop
 * opened the handshake, so the peer's static key is the initiator's.
 *
 * Null until the handshake completes, which the handler treats as "cannot
 * bind" and refuses rather than attesting to no channel.
 */
fun NoiseSession.sessionBinding(): SessionBinding? {
    if (!isHandshakeComplete()) return null
    val initiator = getRemoteStaticKey() ?: return null
    val responder = getStaticPublicKey() ?: return null
    return SessionBinding(initiator, responder, getPrologue())
}

/**
 * The same binding for a session this phone opened as the Noise **initiator**
 * — [BleClient] dialling a desktop's GATT server. The roles are the
 * handshake's, not the devices': here the phone's static key is the
 * initiator's and the desktop's is the responder's.
 *
 * Null until the handshake completes.
 */
fun NoiseInitiatorSession.sessionBinding(): SessionBinding? {
    if (!isHandshakeComplete()) return null
    val responder = getRemoteStaticKey() ?: return null
    return SessionBinding(getLocalStaticPublicKey(), responder, getPrologue())
}
