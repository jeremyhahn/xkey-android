/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ble

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.DataInputStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.security.MessageDigest
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * The byte layouts [GattServer] derives on its own: the Noise prologue, the
 * stored hex fingerprints, and the enrolment PCR blob. They are private pure
 * helpers with no radio or framework call, so they are driven here by
 * reflection on a server that is never started.
 */
class GattServerWireHelpersTest {

    private companion object {
        val prologueMethod =
            declaredMethod("computePrologueFromIdentity", ByteArray::class.java, ByteArray::class.java)
        val hexStringMethod = declaredMethod("hexStringToByteArray", String::class.java)
        val serializePcrMethod = declaredMethod("serializePCRValues", Map::class.java)

        fun declaredMethod(name: String, vararg types: Class<*>): Method = try {
            GattServer::class.java.getDeclaredMethod(name, *types).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw AssertionError(
                "GattServer.$name is a seam this test drives; if it was renamed " +
                    "or reshaped, update GattServerWireHelpersTest",
                e
            )
        }

        fun randomKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    private lateinit var server: GattServer

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        server = GattServer(
            mockk<Context>(relaxed = true),
            mockk<RequestHandler>(relaxed = true),
            pairingCallback = mockk(),
            pairedDeviceRepository = PairedDeviceRepository(InMemorySharedPreferences()),
        )
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    /**
     * The prologue formula is a cross-language contract with
     * `go-xkms/xkey/pkg/pairing`; the two sides derive it independently and a
     * mismatch shows up only as an unexplained handshake failure.
     */
    @Test
    fun thePrologueFormulaIsSha256OfKeyFingerprintAndVersion() {
        val publicKey = randomKey()
        val fingerprint = randomKey()

        val expected = MessageDigest.getInstance("SHA-256").run {
            update(publicKey)
            update(fingerprint)
            update("xkey-v1".toByteArray(Charsets.UTF_8))
            digest()
        }

        assertArrayEquals(expected, computePrologueFromIdentity(publicKey, fingerprint))
    }

    /** Fingerprints are stored as hex and put on the wire as bytes. */
    @Test
    fun hexFingerprintsDecodeToTheirBytes() {
        val bytes = randomKey()
        val hex = bytes.joinToString("") { "%02x".format(it) }

        assertArrayEquals(bytes, hexStringToByteArray(hex))
        assertArrayEquals(
            byteArrayOf(0x00, 0x0f.toByte(), 0xf0.toByte(), 0xff.toByte()),
            hexStringToByteArray("000ff0ff")
        )
        assertEquals(0, hexStringToByteArray("").size)
    }

    /**
     * Enrolment stores the baseline PCR set as an opaque blob. The layout is
     * `[count][index][len][value]…`; nothing else reads it back, so the shape
     * is pinned here.
     */
    @Test
    fun pcrValuesSerialiseToTheDocumentedLayout() {
        val pcrValues = linkedMapOf(
            0 to ByteArray(32) { 0x11 },
            7 to ByteArray(20) { 0x22 }
        )

        val stream = DataInputStream(serializePCRValues(pcrValues).inputStream())
        assertEquals(2, stream.readInt())

        assertEquals(0, stream.readInt())
        assertEquals(32, stream.readInt())
        assertArrayEquals(ByteArray(32) { 0x11 }, ByteArray(32).also { stream.readFully(it) })

        assertEquals(7, stream.readInt())
        assertEquals(20, stream.readInt())
        assertArrayEquals(ByteArray(20) { 0x22 }, ByteArray(20).also { stream.readFully(it) })

        assertEquals("nothing trails the last value", 0, stream.available())
    }

    @Test
    fun anEmptyPcrSetSerialisesToACountOfZero() {
        val encoded = serializePCRValues(emptyMap())

        assertEquals(4, encoded.size)
        assertEquals(0, DataInputStream(encoded.inputStream()).readInt())
    }

    private fun computePrologueFromIdentity(publicKey: ByteArray, fingerprint: ByteArray): ByteArray =
        invoke(prologueMethod, publicKey, fingerprint) as ByteArray

    private fun hexStringToByteArray(hex: String): ByteArray =
        invoke(hexStringMethod, hex) as ByteArray

    private fun serializePCRValues(pcrValues: Map<Int, ByteArray>): ByteArray =
        invoke(serializePcrMethod, pcrValues) as ByteArray

    private fun invoke(method: Method, vararg args: Any?): Any? = try {
        method.invoke(server, *args)
    } catch (e: InvocationTargetException) {
        throw e.cause ?: e
    }
}
