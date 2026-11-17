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
package com.automatethethings.xkey.transport

import com.automatethethings.xkey.ble.GattServer
import com.automatethethings.xkey.remote.ConnectionSenders
import com.automatethethings.xkey.remote.stubAndroidLog
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.usb.UsbAccessoryServer
import io.mockk.unmockkAll
import java.io.IOException
import java.lang.reflect.Field
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A transport's bound senders live only as long as their connection: the one
 * cache that holds them ([ConnectionSenders]) drops a connection's sender when
 * it ends and zeroes its session keys, and no transport keeps a sender
 * anywhere else.
 */
class BoundSenderLifecycleTest {

    @Before
    fun setUp() = stubAndroidLog()

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a stream teardown drops the cached sender and zeroes the session keys`() = runBlocking {
        StreamSessionHarness().use { harness ->
            val desktop = harness.connectPaired()
            val noise = harness.pairing.activeNoiseForTest()!!
            val keys = noise.secretArraysForTest().filterKeys { it == "sendKey" || it == "recvKey" }
            assertEquals("the session has its traffic keys", 2, keys.size)
            val sender = harness.pairing.boundSender()!!.second
            assertTrue("the connection's sender is cached", !harness.pairing.sendersEmptyForTest)

            desktop.close()

            eventually("the ended connection's sender is dropped") { harness.pairing.sendersEmptyForTest }
            eventually("the session keys are zeroed") { keys.values.all { k -> k.all { it == 0.toByte() } } }
            assertNull("a lookup after the end finds nothing", harness.pairing.boundSender())
            try {
                sender.sendEncryptedMessage("""{"jsonrpc":"2.0","id":3,"method":"remote.ping"}""".toByteArray())
                fail("a send on the ended connection must be refused")
            } catch (e: IOException) {
                // The connection ended.
            }
        }
    }

    /**
     * Every transport that binds senders caches them only in its one
     * [ConnectionSenders]: no field of the transport, or of a class nested in
     * it, holds a sender (or a pair, list or map of them) outside it.
     */
    @Test
    fun `no transport caches a sender outside its connection-owned cache`() {
        val binders = listOf(GattServer::class.java, StreamPairingSession::class.java)
        for (transport in binders) {
            val owners = transport.declaredFields.filter { it.type == ConnectionSenders::class.java }
            assertEquals("${transport.simpleName} has one sender cache", 1, owners.size)
        }
        val transports = binders + listOf(TcpHsmServer::class.java, UsbAccessoryServer::class.java)
        val strays = transports.flatMap { senderFields(it) }
        assertTrue("senders cached outside ConnectionSenders: $strays", strays.isEmpty())
    }

    private fun senderFields(type: Class<*>): List<String> =
        type.declaredFields.filter { it.holdsSender() }.map { "${type.name}.${it.name}" } +
            type.declaredClasses.flatMap { senderFields(it) }

    private fun Field.holdsSender(): Boolean = genericType.typeName.contains("SessionSender")

    private fun eventually(what: String, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (!check()) {
            if (System.currentTimeMillis() > deadline) fail("timed out waiting until $what")
            Thread.sleep(10)
        }
    }

    private companion object {
        const val TIMEOUT_MS = 10_000L
    }
}
