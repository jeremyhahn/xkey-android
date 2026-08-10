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
}
