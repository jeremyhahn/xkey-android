/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.ble.fido

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Every fidoStatus notification goes through `sendNext`, which sends nothing
 * to a client that is not subscribed, and the subscription changes only in
 * `onSubscription`, which drops the queued frames when it ends. No other
 * code notifies the stack or sets the subscription.
 */
class FidoNotifyChokePointTest {

    private val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    private val fido = root.walkTopDown()
        .filter { it.isFile && it.extension == "kt" && it.path.replace('\\', '/').contains("/xkey/ble/fido/") }
        .toList()
    private val server = fido.single { it.name == "FidoGattServer.kt" }.readText()

    @Test
    fun `only the FIDO GATT server's notify helpers call the stack`() {
        val calls = Regex("""\.notifyCharacteristicChanged\s*\(""")
        assertEquals(emptyList<String>(), fido.filter { it.name != "FidoGattServer.kt" && calls.containsMatchIn(it.readText()) }.map { it.name })
        assertEquals("one call per API path", 2, calls.findAll(server).count())
    }

    @Test
    fun `the notify helper is called only from sendNext`() {
        val calls = Regex("""\bnotify\(s, characteristic, frame\)""").findAll(server).toList()
        assertEquals(1, calls.size)
        val body = server.substringAfter("private fun sendNext()").substringBefore("private fun fail()")
        assertEquals(true, body.contains("notify(s, characteristic, frame)"))
        assertEquals(true, body.contains("!subscribed) return"))
    }

    @Test
    fun `the subscription is set only in onSubscription`() {
        assertEquals(1, Regex("""(?<!var )\bsubscribed\s*=(?!=)""").findAll(server).count())
        assertEquals(true, server.substringAfter("fun onSubscription(").substringBefore("}\n\n").contains("subscribed = on"))
        assertEquals(1, Regex("""\.onSubscription\(""").findAll(server).count())
    }
}
