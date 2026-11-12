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

import com.automatethethings.xkey.protocol.RemoteAttestDeviceResult
import java.util.Base64

/**
 * A desktop transport with a connection on it: what sends to the desktop and
 * the router its replies come back on.
 *
 * @property established whether the encrypted session is up; false while the
 *   handshake still runs
 */
class DesktopTransport(
    val sender: MessageSender,
    val router: BidirectionalMessageRouter,
    val established: Boolean
)

/** The desktop the phone serves now: its confirmed peer key and the key client on its own transport. */
class DesktopPeerSession(val peerPublicKeyHex: String, val client: RemoteKeyClient)

/**
 * The phone's outbound `remote.*` key clients and the desktop each one reaches.
 *
 * Each [RemoteKeyClient] numbers its own requests and a router matches
 * replies by id, so every key call on a router, device attestation included,
 * goes through the one client kept here for that router.
 *
 * The confirmed peer is one value shared by BLE, TCP and USB: whichever
 * transport confirmed last wrote it, and each clears it when its session
 * ends. It names the desktop on a transport only while that transport is the
 * only one with a connection, so [session] answers only then. With a second
 * connection up or still handshaking it answers null rather than pair one
 * desktop's identity with another desktop's client.
 *
 * @param transports the transports with a connection, in priority order
 * @param confirmedPeer the confirmed peer public key hex, or null
 */
class DesktopSessions(
    private val transports: () -> List<DesktopTransport>,
    private val confirmedPeer: () -> String?
) {
    private var cached: Pair<BidirectionalMessageRouter, RemoteKeyClient>? = null

    /** The key client of the first transport with an established session, or null when there is none. */
    @Synchronized
    fun client(): RemoteKeyClient? = transports().firstOrNull { it.established }?.let(::clientFor)

    /**
     * The confirmed peer and the client of its transport, read together, or
     * null unless exactly one transport has a connection, its session is
     * established and its peer is confirmed.
     */
    @Synchronized
    fun session(): DesktopPeerSession? {
        val only = transports().singleOrNull()?.takeIf { it.established } ?: return null
        val peer = confirmedPeer() ?: return null
        return DesktopPeerSession(peer, clientFor(only))
    }

    /**
     * Asks [peer] for its device attestation (`remote.attestDevice`) over
     * [nonce], or returns null when [peer] is not the desktop [session] names.
     */
    suspend fun attestDevice(peer: String, nonce: ByteArray): RemoteAttestDeviceResult? {
        val session = session()?.takeIf { it.peerPublicKeyHex == peer } ?: return null
        return session.client.attestDevice(Base64.getEncoder().encodeToString(nonce))
    }

    private fun clientFor(transport: DesktopTransport): RemoteKeyClient {
        cached?.let { (router, client) -> if (router === transport.router) return client }
        return RemoteKeyClient(transport.sender, transport.router).also { cached = transport.router to it }
    }
}
