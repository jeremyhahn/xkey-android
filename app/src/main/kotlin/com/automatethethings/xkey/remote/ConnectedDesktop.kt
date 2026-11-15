/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.remote

/**
 * A [MessageSender] bound to one connection's session: it sends only on the
 * connection it was captured from and fails with [java.io.IOException] once
 * that connection ends or another peer replaces it. It never re-resolves the
 * transport's active connection at send time.
 *
 * Only a transport's session binder makes one (`StreamPairingSession`
 * for TCP and USB, `GattServer` for BLE); a transport server is never one.
 */
interface SessionSender : MessageSender

/**
 * A desktop with an established session on one transport: the peer's static
 * key as authenticated by the Noise handshake ([peerKeyHex], lowercase hex)
 * and the [sender] and [router] that reach it. [sender] is bound to the
 * connection whose handshake authenticated [peerKeyHex], so whatever is sent
 * through it reaches that desktop or nobody. State a phone keeps about a
 * desktop is keyed by [peerKeyHex], never by the transport.
 *
 * Every outbound `remote.*` client is built from one: it is the one choke
 * point between a desktop's identity and the connection that carries it.
 */
class ConnectedDesktop(
    peerKeyHex: String,
    val sender: SessionSender,
    val router: BidirectionalMessageRouter
) {
    val peerKeyHex: String = peerKeyHex.lowercase()

    companion object {
        /**
         * A [ConnectedDesktop] if [established] and the bound [session] (the
         * authenticated key and its connection's sender) and [router] are
         * known, else null.
         */
        fun ifEstablished(
            established: Boolean,
            session: Pair<String, SessionSender>?,
            router: BidirectionalMessageRouter?
        ): ConnectedDesktop? =
            if (established && session != null && router != null) {
                ConnectedDesktop(session.first, session.second, router)
            } else {
                null
            }
    }
}
