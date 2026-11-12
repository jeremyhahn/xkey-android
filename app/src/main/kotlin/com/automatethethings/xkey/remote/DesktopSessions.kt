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
import java.io.IOException
import java.lang.ref.WeakReference
import java.util.Base64
import java.util.WeakHashMap

/**
 * A desktop transport with a connection on it: what sends to the desktop and
 * the router its replies come back on.
 *
 * @property established whether the encrypted session is up; false while the
 *   handshake still runs
 * @property confirmedPeer the peer public key hex this transport's own session
 *   confirmed, or null while it has none
 */
class DesktopTransport(
    val sender: MessageSender,
    val router: BidirectionalMessageRouter,
    val established: Boolean,
    val confirmedPeer: String?
)

/** The desktop the phone serves now: its confirmed peer key and the key client on its own transport. */
class DesktopPeerSession(val peerPublicKeyHex: String, val client: RemoteKeyClient)

/**
 * The phone's outbound `remote.*` key clients and the desktop each one reaches.
 *
 * Each transport reports the peer its own session confirmed, so [session]
 * pairs a desktop's identity only with the client of the transport that
 * confirmed it, never with the request handler's peer, which BLE, TCP and USB
 * share and which a stopped transport can leave behind.
 *
 * A session's client sends only while that transport still carries the
 * desktop it was checked for: right before each send it reads the transports
 * again and refuses with an [IOException] when the connection is gone or now
 * carries another desktop, so a request checked for one desktop never goes
 * out on a replacement connection.
 *
 * @param transports the transports with a connection, in priority order
 */
class DesktopSessions(
    private val transports: () -> List<DesktopTransport>
) {
    /** A router's client and the peer its sends are bound to, or null when unbound. */
    private class Entry(val peer: String?, val client: WeakReference<RemoteKeyClient>)

    /**
     * One client per router and peer, so a switch to another desktop and back
     * reuses the first client while the peer is unchanged. Routers do not
     * override equals, so the map keys by identity. The client is held weakly
     * too, since it holds its router; the request id counter lives on the
     * router, so a client rebuilt after a collection continues its numbering.
     */
    private val clients = WeakHashMap<BidirectionalMessageRouter, Entry>()

    /**
     * The key client of the first transport with an established session, or
     * null when there is none. With a confirmed peer it is that session's
     * peer-bound client.
     */
    @Synchronized
    fun client(): RemoteKeyClient? =
        transports().firstOrNull { it.established }?.let { clientFor(it, it.confirmedPeer) }

    /**
     * The first established transport's confirmed peer and its client, read
     * from one snapshot, or null while that transport has no confirmed peer.
     * The client sends only while that transport still carries that peer.
     */
    @Synchronized
    fun session(): DesktopPeerSession? {
        val active = transports().firstOrNull { it.established } ?: return null
        val peer = active.confirmedPeer ?: return null
        return DesktopPeerSession(peer, clientFor(active, peer))
    }

    /**
     * Asks [peer] for its device attestation (`remote.attestDevice`) over
     * [nonce], or returns null when [peer] is not the desktop [session] names.
     */
    suspend fun attestDevice(peer: String, nonce: ByteArray): RemoteAttestDeviceResult? {
        val session = session()?.takeIf { it.peerPublicKeyHex == peer } ?: return null
        return session.client.attestDevice(Base64.getEncoder().encodeToString(nonce))
    }

    private fun clientFor(transport: DesktopTransport, peer: String?): RemoteKeyClient {
        clients[transport.router]?.takeIf { it.peer == peer }?.client?.get()?.let { return it }
        val sender = peer?.let { PeerBoundSender(transport.sender, transport.router, it) } ?: transport.sender
        return RemoteKeyClient(sender, transport.router)
            .also { clients[transport.router] = Entry(peer, WeakReference(it)) }
    }

    /**
     * Sends through [sender] only while the transport on [router] is still
     * established, still sends through [sender] and still names [peer].
     */
    private inner class PeerBoundSender(
        private val sender: MessageSender,
        private val router: BidirectionalMessageRouter,
        private val peer: String
    ) : MessageSender {
        override suspend fun sendEncryptedMessage(data: ByteArray) {
            val current = transports().firstOrNull { it.router === router }
            if (current == null || !current.established || current.sender !== sender ||
                current.confirmedPeer != peer
            ) {
                throw IOException("desktop session changed; request not sent")
            }
            sender.sendEncryptedMessage(data)
        }
    }
}
