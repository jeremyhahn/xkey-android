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
 * A desktop with an established session on one transport: the peer's static
 * key as authenticated by the Noise handshake ([peerKeyHex], lowercase hex)
 * and the [sender] and [router] that reach it. State a phone keeps about a
 * desktop is keyed by [peerKeyHex], never by the transport.
 */
class ConnectedDesktop(
    peerKeyHex: String,
    val sender: MessageSender,
    val router: BidirectionalMessageRouter
) {
    val peerKeyHex: String = peerKeyHex.lowercase()

    companion object {
        /** A [ConnectedDesktop] if [established] and both the key and router are known, else null. */
        fun ifEstablished(
            established: Boolean,
            peerKeyHex: String?,
            sender: MessageSender,
            router: BidirectionalMessageRouter?
        ): ConnectedDesktop? =
            if (established && peerKeyHex != null && router != null) {
                ConnectedDesktop(peerKeyHex, sender, router)
            } else {
                null
            }
    }
}
