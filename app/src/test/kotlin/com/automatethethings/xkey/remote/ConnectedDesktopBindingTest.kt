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
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.transport.StreamPairingSession
import com.automatethethings.xkey.usb.UsbAccessoryServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every outbound `remote.*` send goes through a [ConnectedDesktop], whose
 * [SessionSender] is bound to the one connection that authenticated its key
 * (ruling 554, #141). A client that could take a transport's own
 * [MessageSender] would send on whichever session the transport holds at
 * send time, so a peer that replaced the captured one would receive it.
 *
 * The sweep covers the four `remote.*` clients, the four transport senders
 * (TCP, USB, BLE/GATT and the stream session they share) and the service
 * that builds the clients. `protocol.MessageSender` is not a send path:
 * nothing in the app installs one.
 */
class ConnectedDesktopBindingTest {

    private val clients = listOf(
        RemoteSyncClient::class.java,
        RemoteBackupClient::class.java,
        RemoteKeyClient::class.java,
        RemoteOathClient::class.java,
    )

    private val transports = listOf(
        TcpHsmServer::class.java,
        UsbAccessoryServer::class.java,
        GattServer::class.java,
        StreamPairingSession::class.java,
    )

    @Test
    fun noRemoteClientTakesASenderThatIsNotAConnectedDesktop() {
        clients.forEach { client ->
            client.declaredConstructors.forEach { constructor ->
                val types = constructor.parameterTypes
                types.forEach { type ->
                    assertFalse(
                        "${client.simpleName} takes a ${type.simpleName}, a sender not bound to a desktop",
                        MessageSender::class.java.isAssignableFrom(type)
                    )
                }
                assertTrue(
                    "${client.simpleName} must be built from a ConnectedDesktop",
                    types.contains(ConnectedDesktop::class.java)
                )
            }
        }
    }

    @Test
    fun noRemoteClientSetsItsSenderAfterConstruction() {
        clients.forEach { client ->
            client.declaredMethods.forEach { method ->
                method.parameterTypes.forEach { type ->
                    assertFalse(
                        "${client.simpleName}.${method.name} takes a ${type.simpleName}",
                        MessageSender::class.java.isAssignableFrom(type)
                    )
                }
            }
        }
    }

    @Test
    fun aConnectedDesktopSendsOnlyThroughABoundSessionSender() {
        val constructor = ConnectedDesktop::class.java.declaredConstructors.single()
        assertEquals(
            listOf(String::class.java, SessionSender::class.java, BidirectionalMessageRouter::class.java),
            constructor.parameterTypes.toList()
        )
    }

    @Test
    fun noTransportIsItselfABoundSender() {
        transports.forEach { transport ->
            assertFalse(
                "${transport.simpleName} re-resolves its session at send time; it must hand out bound senders",
                SessionSender::class.java.isAssignableFrom(transport)
            )
        }
    }

    @Test
    fun theServiceHandsOutNoUnboundSender() {
        val methods = XKeyGattService::class.java.declaredMethods
        assertFalse(
            "activeTransport() handed out a transport's own sender",
            methods.any { it.name == "activeTransport" }
        )
        // Compiler-made field accessors (access$get...) are not API.
        methods.filterNot { it.isSynthetic }.forEach { method ->
            assertFalse(
                "XKeyGattService.${method.name} returns a ${method.returnType.simpleName}",
                MessageSender::class.java.isAssignableFrom(method.returnType)
            )
        }
    }
}
