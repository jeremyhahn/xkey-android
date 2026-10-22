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

package com.automatethethings.xkey.usb

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.storage.SealStore
import com.automatethethings.xkey.transport.StreamMessageFraming
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.Base64

/**
 * [SealStoreMethods] sizes a sealed secret by the `SealStoreGet` response
 * Android's own org.json writes. That writer escapes '/' as `\/`, which the
 * JVM org.json of the unit tests and Go's encoder do not, so a base64 secret
 * of 0xff bytes (all '/') serializes to twice its length only here.
 *
 * Runs against the real Android Keystore; the test owns a per-run alias and a
 * directory and deletes both in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class SealStoreFrameBudgetTest {

    private val alias = "xkey_test_seal_frame_${System.nanoTime()}"
    private lateinit var dir: File
    private lateinit var store: SealStore
    private lateinit var methods: SealStoreMethods
    private var nextId = 1L

    /** The Poly1305 tag Noise adds to every message. */
    private val noiseTagSize = 16

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dir = File(context.cacheDir, alias).apply { mkdirs() }
        store = SealStore(dir, KeystoreAeadCipher(alias))
        methods = SealStoreMethods(store)
    }

    @After
    fun tearDown() {
        dir.deleteRecursively()
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private fun call(method: String, params: JSONObject): Response =
        runBlocking { methods.handle(Request(nextId++, method, params)) }

    private fun putParams(name: String, secret: ByteArray): JSONObject = JSONObject().apply {
        put("name", name)
        put("secret", Base64.getEncoder().encodeToString(secret))
    }

    /** [size] bytes of 0xff, whose base64 is all '/'. */
    private fun slashSecret(size: Int): ByteArray = ByteArray(size) { -1 }

    private fun fitsFrame(response: Response): Boolean =
        response.toJson().size + noiseTagSize <= StreamMessageFraming.MAX_MESSAGE_SIZE

    @Test
    fun androidJsonEscapesTheBase64Slash() {
        // The precondition of this suite: without it the escaping regression is not exercised.
        assertEquals("""{"s":"\/"}""", JSONObject().put("s", "/").toString())
    }

    @Test
    fun putRefusesSlashHeavySecretThatFitsByBase64LengthButNotOnceEscaped() {
        // 30,000 bytes are 40,000 base64 slashes, within the frame by length,
        // but Android writes them as 80,000 bytes.
        val secret = slashSecret(30_000)
        val encoded = Base64.getEncoder().encodeToString(secret)
        val unescaped = """{"name":"big","secret":"$encoded"}""".length
        assertTrue("fits by base64 length", unescaped + noiseTagSize < StreamMessageFraming.MAX_MESSAGE_SIZE)

        val refused = call("SealStorePut", putParams("big", secret))

        assertEquals(ErrorCodes.INVALID_PARAMS, refused.error!!.code)
        assertEquals(emptyList<String>(), runBlocking { store.list() })
    }

    @Test
    fun slashHeavySecretThatFitsOnceEscapedRoundTripsThroughGet() {
        // 15,000 bytes are 20,000 slashes, 40,000 bytes once escaped.
        val secret = slashSecret(15_000)

        val put = call("SealStorePut", putParams("big", secret))
        val get = call("SealStoreGet", JSONObject().put("name", "big"))

        assertNull("unexpected error: ${put.error?.message}", put.error)
        assertNull("unexpected error: ${get.error?.message}", get.error)
        assertArrayEquals(secret, Base64.getDecoder().decode(get.result!!.getString("secret")))
        assertTrue("the Get response fits the frame", fitsFrame(get))
    }

    @Test
    fun getOfStoredSlashHeavySecretOverTheFrameIsAnErrorAndTheHandlerKeepsServing() {
        // Stored behind the handler, as a secret written before Put measured it.
        runBlocking {
            store.put("big", slashSecret(30_000))
            store.put("small", slashSecret(3))
        }

        val refused = call("SealStoreGet", JSONObject().put("name", "big"))
        val next = call("SealStoreGet", JSONObject().put("name", "small"))

        assertEquals(ErrorCodes.INTERNAL_ERROR, refused.error!!.code)
        assertTrue(fitsFrame(refused))
        assertArrayEquals(slashSecret(3), Base64.getDecoder().decode(next.result!!.getString("secret")))
    }
}
