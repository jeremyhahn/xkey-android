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
 * Abstraction for sending encrypted messages over the Noise channel.
 *
 * Implemented by both the BLE GATT server and TCP HSM server to allow
 * the [RemoteKeyClient] to send outbound requests regardless of transport.
 */
interface MessageSender {
    /**
     * Sends an encrypted message to the connected peer.
     *
     * The message will be encrypted with the active Noise session before
     * transmission.
     *
     * @param data The plaintext message bytes to encrypt and send.
     * @throws java.io.IOException if the message could not be sent.
     */
    suspend fun sendEncryptedMessage(data: ByteArray)

    /**
     * The peer confirmed on the connection this sender reaches right now,
     * read from that connection alone, or null when it confirms no one (no
     * connection, not yet confirmed, revoked or ended). Never the request
     * handler's one peer key, which another transport's session may have set
     * and a deferred teardown may not have cleared yet.
     */
    fun confirmedConnection(): ConfirmedConnection? = null

    /**
     * Sends [data] encrypted on [connection] alone. The transport checks, at
     * the admission that consumes the nonce, that [connection] is still its
     * current connection, confirmed for the same peer; otherwise it encrypts
     * and writes nothing and throws [ConnectionChangedException]. It never
     * falls back to whatever connection is current at send time.
     *
     * A transport that cannot scope a send to one connection keeps this
     * default, which fails closed.
     *
     * @throws ConnectionChangedException if [connection] is no longer current
     * @throws java.io.IOException if the message could not be sent
     */
    suspend fun sendEncryptedMessageOn(connection: ConfirmedConnection, data: ByteArray): Unit =
        throw ConnectionChangedException()
}

/**
 * One live connection's confirmed peer. [connection] is the connection
 * itself, compared by identity, so the same peer on a later connection is
 * another one.
 */
class ConfirmedConnection(val peerPublicKeyHex: String, val connection: Any) {

    /** The same connection, confirmed for the same peer. */
    fun sameAs(other: ConfirmedConnection?): Boolean =
        other != null && other.connection === connection && other.peerPublicKeyHex == peerPublicKeyHex
}

/** The connection a send was scoped to is no longer the transport's current, confirmed one. */
open class ConnectionChangedException(
    message: String = "the connection changed before the send"
) : java.io.IOException(message)
