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

import com.automatethethings.xkey.ble.GattServer
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.transport.StreamPairingSession
import com.automatethethings.xkey.usb.UsbAccessoryServer
import io.mockk.mockk
import java.io.IOException

/*
 * A transport sends only through the SessionSender bound to its current
 * connection (ruling 554, #141). These capture that sender at the call and
 * send on it, as a remote client does with its ConnectedDesktop; with no
 * established session there is nothing to send on.
 */

internal suspend fun StreamPairingSession.sendOnBoundSession(data: ByteArray) =
    bound(boundSender()?.second).sendEncryptedMessage(data)

internal suspend fun GattServer.sendOnBoundSession(data: ByteArray) =
    bound(boundSender()?.second).sendEncryptedMessage(data)

internal suspend fun TcpHsmServer.sendOnBoundSession(data: ByteArray) =
    bound(connectedDesktop(anyRouter())?.sender).sendEncryptedMessage(data)

internal suspend fun UsbAccessoryServer.sendOnBoundSession(data: ByteArray) =
    bound(connectedDesktop(anyRouter())?.sender).sendEncryptedMessage(data)

private fun anyRouter() = BidirectionalMessageRouter(mockk<RequestHandler>(relaxed = true))

private fun bound(sender: SessionSender?): SessionSender =
    sender ?: throw IOException("No active Noise session")
