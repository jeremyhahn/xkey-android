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
import java.lang.ref.WeakReference
import java.util.Base64
import java.util.WeakHashMap

/**
 * A desktop transport with a connection on it: the [desktop] its session
 * authenticated, whose sender is bound to that connection, and the router its
 * replies come back on.
 *
 * @property established whether the encrypted session is up; false while the
 *   handshake still runs
 * @property confirmedPeer the peer public key hex this transport's own session
 *   confirmed, or null while it has none
 */
class DesktopTransport(
    val desktop: ConnectedDesktop,
    val established: Boolean,
    val confirmedPeer: String?
) {
    /** The sender bound to [desktop]'s connection. */
    val sender: SessionSender get() = desktop.sender

    val router: BidirectionalMessageRouter get() = desktop.router
}

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
 * A session's client is bound to the connection its peer was checked on:
 * [session] captures that connection's [ConfirmedConnection] and the client
 * sends only through [MessageSender.sendEncryptedMessageOn] with it. The
 * transport refuses, at the admission that consumes the nonce, any send whose
 * connection is no longer its current one confirmed for the same peer, so a
 * request checked for one desktop never goes out on a later connection, even
 * the same desktop's.
 *
 * @param transports the transports with a connection, in priority order
 */
class DesktopSessions(
    private val transports: () -> List<DesktopTransport>
) {
    /**
     * A router's client and the connection its sends are bound to, or none
     * when unbound. Both are held weakly: the client holds its router, and a
     * transport's connection may too, and the router is this map's key.
     */
    private class Entry(bound: ConfirmedConnection?, client: RemoteKeyClient) {
        private val unbound = bound == null
        private val bound = bound?.let { WeakReference(it) }
        private val client = WeakReference(client)

        /** The client when it is bound to [wanted]'s connection, or unbound and [wanted] is null. */
        fun clientFor(wanted: ConfirmedConnection?): RemoteKeyClient? {
            val held = client.get() ?: return null
            if (wanted == null) return held.takeIf { unbound }
            return held.takeIf { bound?.get()?.sameAs(wanted) == true }
        }
    }

    /**
     * One client per router and connection, so the screen reuses one client
     * while the connection is unchanged. Routers do not override equals, so
     * the map keys by identity. The request id counter lives on the router,
     * so a client rebuilt for a new connection continues its numbering.
     */
    private val clients = WeakHashMap<BidirectionalMessageRouter, Entry>()

    /**
     * The key client of the first transport with an established session, or
     * null when there is none or its confirmed peer is not the one on its
     * live connection. With a confirmed peer it is bound to that connection;
     * before confirmation it is unbound.
     */
    @Synchronized
    fun client(): RemoteKeyClient? {
        val active = transports().firstOrNull { it.established } ?: return null
        val peer = active.confirmedPeer ?: return clientFor(active, null)
        return clientFor(active, confirmed(active, peer) ?: return null)
    }

    /**
     * The first established transport's confirmed peer and a client bound to
     * the connection that peer is confirmed on, read from one snapshot, or
     * null while that transport has no confirmed peer.
     */
    @Synchronized
    fun session(): DesktopPeerSession? {
        val active = transports().firstOrNull { it.established } ?: return null
        val peer = active.confirmedPeer ?: return null
        val connection = confirmed(active, peer) ?: return null
        return DesktopPeerSession(peer, clientFor(active, connection))
    }

    /**
     * Asks [peer] for its device attestation (`remote.attestDevice`) over
     * [nonce], or returns null when [peer] is not the desktop [session] names.
     */
    suspend fun attestDevice(peer: String, nonce: ByteArray): RemoteAttestDeviceResult? {
        val session = session()?.takeIf { it.peerPublicKeyHex == peer } ?: return null
        return session.client.attestDevice(Base64.getEncoder().encodeToString(nonce))
    }

    /** [transport]'s live connection when it is confirmed for [peer], else null. */
    private fun confirmed(transport: DesktopTransport, peer: String): ConfirmedConnection? =
        transport.sender.confirmedConnection()?.takeIf { it.peerPublicKeyHex == peer }

    private fun clientFor(transport: DesktopTransport, bound: ConfirmedConnection?): RemoteKeyClient {
        clients[transport.router]?.clientFor(bound)?.let { return it }
        val sender = bound?.let { ConnectionBoundSender(transport.sender, it) } ?: transport.sender
        return RemoteKeyClient(ConnectedDesktop(transport.desktop.peerKeyHex, sender, transport.router))
            .also { clients[transport.router] = Entry(bound, it) }
    }

    /**
     * Sends only on [connection], through [sender]'s connection-scoped send,
     * which refuses with [ConnectionChangedException] once [connection] is no
     * longer the transport's current, confirmed one.
     */
    private class ConnectionBoundSender(
        private val sender: MessageSender,
        private val connection: ConfirmedConnection
    ) : SessionSender {
        override suspend fun sendEncryptedMessage(data: ByteArray) =
            sender.sendEncryptedMessageOn(connection, data)
    }
}
