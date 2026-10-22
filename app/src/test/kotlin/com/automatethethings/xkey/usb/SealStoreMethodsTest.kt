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
package com.automatethethings.xkey.usb

import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.storage.SealStore
import com.automatethethings.xkey.storage.SealStoreUnreadableException
import com.automatethethings.xkey.transport.StreamMessageFraming
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.util.Base64

/**
 * Unit tests for [SealStoreMethods] and the [SealStore] behind it: each of the
 * six seal-store methods with go-xkms' exact JSON names, its response shape,
 * and an error path. `secret` is a Go `[]byte`, so it travels as base64.
 *
 * The Keystore is stubbed with a reversible marker transform, as the password
 * repository's tests do; the files are real, in a temporary folder.
 */
class SealStoreMethodsTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val marker: Byte = 0x7f
    private lateinit var cipher: KeystoreAeadCipher
    private lateinit var dir: File
    private lateinit var store: SealStore
    private lateinit var methods: SealStoreMethods
    private var nextId = 1L

    private val secret = byteArrayOf(0, 1, 2, 3, -1)
    private val secretB64 = "AAECA/8="

    @Before
    fun setUp() {
        cipher = mockk()
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
        dir = tmp.newFolder("seal_store")
        store = SealStore(dir, cipher)
        methods = SealStoreMethods(store)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private suspend fun call(method: String, params: String? = null, on: SealStoreMethods = methods): Response =
        on.handle(Request(nextId++, method, params?.let { JSONObject(it) }))

    private fun Response.ok(): JSONObject {
        assertNull("unexpected error: ${error?.message}", error)
        return result!!
    }

    private fun Response.code(): Int = error!!.code

    private suspend fun putSecret(name: String) =
        call("SealStorePut", """{"name":"$name","secret":"$secretB64"}""").ok()

    /** A name of exactly [SealStoreMethods.MAX_NAME_BYTES] bytes, sorting by [i]. */
    private fun longName(i: Int): String = "secret-%03d-".format(i).padEnd(SealStoreMethods.MAX_NAME_BYTES, 'x')

    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }

    /** The response, once Noise adds its tag, fits one USB frame. */
    private fun assertFitsFrame(response: Response) {
        val ciphertext = response.toJson().size + FrameBudget.NOISE_TAG_SIZE
        assertTrue("$ciphertext bytes exceed the frame", ciphertext <= StreamMessageFraming.MAX_MESSAGE_SIZE)
    }

    /** Whether appending [next] to [result]'s name array would leave the budget. */
    private fun nextNameOverflows(result: JSONObject, next: String): Boolean {
        val size = result.toString().toByteArray(Charsets.UTF_8).size
        return size + JSONObject.quote(next).toByteArray(Charsets.UTF_8).size + 1 > FrameBudget.RESULT_BUDGET
    }

    /** The page_size a refused `SealStoreList` page names as fitting. */
    private fun suggestedPageSize(refused: Response): Int {
        val match = Regex("""page_size of at most (\d+)""").find(refused.error!!.message)
        return match!!.groupValues[1].toInt()
    }

    private fun failingMethods(): SealStoreMethods {
        val broken = mockk<SealStore>()
        coEvery { broken.list() } throws IOException("cannot read /data/secret-name")
        return SealStoreMethods(broken)
    }

    private suspend fun call(method: String, params: JSONObject, on: SealStoreMethods = methods): Response =
        on.handle(Request(nextId++, method, params))

    private fun secretOf(size: Int): ByteArray = ByteArray(size) { -1 }

    /**
     * The size of the `SealStoreGet` result for [size] bytes of 0xff under
     * [name], written by the serializer the code measures with, so the tests
     * hold whether or not this org.json escapes the base64 '/'.
     */
    private fun getResultSize(name: String, size: Int): Int = FrameBudget.serializedSize(
        JSONObject().apply {
            put("name", name)
            put("secret", Base64.getEncoder().encodeToString(secretOf(size)))
        }
    )

    /** The most bytes of 0xff whose `SealStoreGet` result under [name] fits the budget. */
    private fun largestFittingSecret(name: String): Int {
        var lo = 0
        // A secret of RESULT_BUDGET bytes base64-encodes to more than RESULT_BUDGET characters.
        var hi = FrameBudget.RESULT_BUDGET
        while (lo < hi) {
            val mid = (lo + hi + 1) / 2
            if (getResultSize(name, mid) <= FrameBudget.RESULT_BUDGET) lo = mid else hi = mid - 1
        }
        return lo
    }

    private fun putParams(name: String, secret: ByteArray): JSONObject = JSONObject().apply {
        put("name", name)
        put("secret", Base64.getEncoder().encodeToString(secret))
    }

    @Test
    fun `the family claims exactly the six seal-store methods`() {
        for (m in listOf(
            "SealStorePut", "SealStoreGet", "SealStoreDelete",
            "SealStoreList", "SealStoreReseal", "SealStoreStatus"
        )) {
            assertTrue(m, methods.handles(m))
        }
        assertFalse(methods.handles("PasswordGet"))
    }

    // -------------------------------------------------------------------------
    // SealStorePut
    // -------------------------------------------------------------------------

    @Test
    fun `SealStorePut decodes the base64 secret, seals it and answers an empty result`() = runTest {
        val result = putSecret("disk-key")

        assertEquals(0, result.length())
        assertArrayEquals(secret, store.get("disk-key"))
        val onDisk = dir.listFiles()!!.single { it.name.endsWith(".sealed") }.readBytes()
        assertFalse("the plaintext must not reach the disk", onDisk.contentEquals(secret))
    }

    @Test
    fun `SealStorePut with a secret that is not base64 is invalid params`() = runTest {
        val response = call("SealStorePut", """{"name":"disk-key","secret":"not base64!"}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, response.code())
    }

    @Test
    fun `SealStorePut refuses a name over 1 KiB of UTF-8 and accepts one of exactly 1 KiB`() = runTest {
        // "é" is two UTF-8 bytes, so the limit is on bytes, not characters.
        val atLimit = "é".repeat(SealStoreMethods.MAX_NAME_BYTES / 2)
        val overLimit = atLimit + "a"

        val refused = call("SealStorePut", """{"name":"$overLimit","secret":"$secretB64"}""")
        putSecret(atLimit)

        assertEquals(ErrorCodes.INVALID_PARAMS, refused.code())
        assertEquals(listOf(atLimit), store.list())
    }

    // -------------------------------------------------------------------------
    // SealStoreGet
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreGet answers name and the base64 secret`() = runTest {
        putSecret("disk-key")

        val result = call("SealStoreGet", """{"name":"disk-key"}""").ok()

        assertEquals("disk-key", result.getString("name"))
        assertEquals(secretB64, result.getString("secret"))
        assertArrayEquals(secret, Base64.getDecoder().decode(result.getString("secret")))
    }

    @Test
    fun `SealStoreGet of an unknown name is not found`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreGet", """{"name":"nope"}""").code())
    }

    @Test
    fun `SealStorePut stores a secret whose SealStoreGet response just fits the frame and Get returns it`() = runTest {
        val fitting = secretOf(largestFittingSecret("big"))

        val put = call("SealStorePut", putParams("big", fitting))
        val get = call("SealStoreGet", """{"name":"big"}""")

        put.ok()
        assertArrayEquals(fitting, Base64.getDecoder().decode(get.ok().getString("secret")))
        assertFitsFrame(get)
    }

    @Test
    fun `SealStorePut refuses a secret whose SealStoreGet response would overflow the frame and stores nothing`() =
        runTest {
            val tooLarge = secretOf(largestFittingSecret("big") + 1)

            val refused = call("SealStorePut", putParams("big", tooLarge))

            assertEquals(ErrorCodes.INVALID_PARAMS, refused.code())
            assertTrue(refused.error!!.message, refused.error!!.message.contains("${FrameBudget.RESULT_BUDGET} bytes"))
            assertEquals(emptyList<String>(), store.list())
        }

    @Test
    fun `SealStoreGet of a stored secret too large for the frame is an internal error and the handler keeps serving`() =
        runTest {
            // Stored behind the handler's back, as one written before Put measured it would be.
            store.put("big", secretOf(largestFittingSecret("big") + 1))
            putSecret("disk-key")

            val refused = call("SealStoreGet", """{"name":"big"}""")
            val next = call("SealStoreGet", """{"name":"disk-key"}""")

            assertEquals(ErrorCodes.INTERNAL_ERROR, refused.code())
            assertEquals("sealed secret does not fit the frame", refused.error!!.message)
            assertFitsFrame(refused)
            assertEquals(secretB64, next.ok().getString("secret"))
        }

    @Test
    fun `SealStoreGet zeroes a stored secret too large for the frame before refusing it`() = runTest {
        val stored = secretOf(largestFittingSecret("big") + 1)
        val mocked = mockk<SealStore>()
        coEvery { mocked.get("big") } returns stored

        val refused = call("SealStoreGet", """{"name":"big"}""", SealStoreMethods(mocked))

        assertEquals(ErrorCodes.INTERNAL_ERROR, refused.code())
        assertTrue("the plaintext must be zeroed", stored.all { it == 0.toByte() })
    }

    // -------------------------------------------------------------------------
    // SealStoreDelete
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreDelete removes the secret and answers an empty result`() = runTest {
        putSecret("disk-key")

        val result = call("SealStoreDelete", """{"name":"disk-key"}""").ok()

        assertEquals(0, result.length())
        assertNull(store.get("disk-key"))
        assertTrue(store.list().isEmpty())
        assertTrue("ciphertext and name both removed", dir.listFiles()!!.isEmpty())
    }

    @Test
    fun `SealStoreDelete of an unknown name is not found`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreDelete", """{"name":"nope"}""").code())
    }

    @Test
    fun `SealStoreDelete that cannot unlink the ciphertext is an internal error and keeps the name listed`() = runTest {
        putSecret("disk-key")
        // A non-empty directory in place of the ciphertext: its unlink fails, even as root.
        val sealed = dir.listFiles()!!.single { it.name.endsWith(".sealed") }
        assertTrue(sealed.delete())
        assertTrue(File(sealed, "child").mkdirs())

        val response = call("SealStoreDelete", """{"name":"disk-key"}""")

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.code())
        assertEquals(listOf("disk-key"), call("SealStoreList").ok().getJSONArray("names").strings())
        val status = call("SealStoreStatus").ok()
        assertEquals(1, status.getInt("secret_count"))
        assertEquals(listOf("disk-key"), status.getJSONArray("secret_names").strings())
    }

    @Test
    fun `SealStorePut that cannot write the name stores no secret that List would hide`() = runTest {
        // A non-empty directory where the name goes: renaming the name into place fails.
        val nameFile = File(dir, SyncCodec.sha256Hex("disk-key".toByteArray(Charsets.UTF_8)) + ".name")
        assertTrue(File(nameFile, "child").mkdirs())

        val response = call("SealStorePut", """{"name":"disk-key","secret":"$secretB64"}""")

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.code())
        assertNull("a secret List cannot see must not be retrievable", store.get("disk-key"))
        assertTrue(store.list().isEmpty())
    }

    // -------------------------------------------------------------------------
    // SealStoreList
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreList answers sorted names with the PageResponse fields`() = runTest {
        putSecret("b")
        putSecret("a/b")
        putSecret("a:b")

        val result = call("SealStoreList").ok()

        val names = result.getJSONArray("names")
        assertEquals(listOf("a/b", "a:b", "b"), (0 until names.length()).map { names.getString(it) })
        assertEquals(0, result.getInt("page"))
        assertEquals(3, result.getInt("page_size"))
        assertEquals(3, result.getInt("total"))
        assertFalse(result.getBoolean("has_more"))
    }

    @Test
    fun `SealStoreList with nil params answers the largest prefix that fits the frame`() = runTest {
        repeat(100) { putSecret(longName(it)) }

        val response = call("SealStoreList")
        val result = response.ok()

        assertFitsFrame(response)
        val names = result.getJSONArray("names").strings()
        assertTrue("100 KiB of names cannot fit one frame", names.size in 1 until 100)
        assertEquals(store.list().take(names.size), names)
        assertEquals(0, result.getInt("page"))
        assertEquals(names.size, result.getInt("page_size"))
        assertEquals(100, result.getInt("total"))
        assertTrue(result.getBoolean("has_more"))
        assertTrue("one more name would not fit", nextNameOverflows(result, store.list()[names.size]))
    }

    @Test
    fun `SealStoreList serves a requested page, the default page size, and a page past the end`() = runTest {
        repeat(30) { putSecret("s%02d".format(it)) }

        val second = call("SealStoreList", """{"page":2,"page_size":10}""").ok()
        assertEquals((10..19).map { "s%02d".format(it) }, second.getJSONArray("names").strings())
        assertEquals(2, second.getInt("page"))
        assertEquals(10, second.getInt("page_size"))
        assertEquals(30, second.getInt("total"))
        assertTrue(second.getBoolean("has_more"))

        val last = call("SealStoreList", """{"page":3,"page_size":10}""").ok()
        assertEquals(10, last.getJSONArray("names").length())
        assertFalse(last.getBoolean("has_more"))

        val defaulted = call("SealStoreList", """{"page":1}""").ok()
        assertEquals(SealStoreMethods.DEFAULT_PAGE_SIZE, defaulted.getInt("page_size"))
        assertEquals(SealStoreMethods.DEFAULT_PAGE_SIZE, defaulted.getJSONArray("names").length())
        assertTrue(defaulted.getBoolean("has_more"))

        val pastTheEnd = call("SealStoreList", """{"page":4,"page_size":10}""").ok()
        assertEquals(0, pastTheEnd.getJSONArray("names").length())
        assertEquals(4, pastTheEnd.getInt("page"))
        assertEquals(30, pastTheEnd.getInt("total"))
        assertFalse(pastTheEnd.getBoolean("has_more"))
    }

    @Test
    fun `SealStoreList refuses an explicit page that overflows the frame and names a page_size that fits`() = runTest {
        repeat(100) { putSecret(longName(it)) }

        val refused = call("SealStoreList", """{"page":1,"page_size":100}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, refused.code())
        assertTrue(refused.error!!.message.startsWith("page 1 does not fit the frame"))
        val fit = suggestedPageSize(refused)
        assertTrue(fit in 1 until 100)
        val page = call("SealStoreList", """{"page":1,"page_size":$fit}""")
        assertFitsFrame(page)
        assertEquals(store.list().take(fit), page.ok().getJSONArray("names").strings())
        val oneMore = call("SealStoreList", """{"page":1,"page_size":${fit + 1}}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, oneMore.code())
    }

    @Test
    fun `SealStoreList pages followed at a page_size that fits list every stored name exactly once`() = runTest {
        repeat(100) { putSecret(longName(it)) }
        val pageSize = suggestedPageSize(call("SealStoreList", """{"page":1,"page_size":100}"""))

        val seen = mutableListOf<String>()
        var page = 1
        do {
            val response = call("SealStoreList", """{"page":$page,"page_size":$pageSize}""")
            assertFitsFrame(response)
            val result = response.ok()
            assertEquals(page, result.getInt("page"))
            assertEquals(100, result.getInt("total"))
            seen += result.getJSONArray("names").strings()
            page++
            assertTrue("paging must end", page <= 100)
        } while (result.getBoolean("has_more"))

        assertEquals(store.list(), seen)
        assertEquals(100, seen.toSet().size)
    }

    @Test
    fun `SealStoreList refuses a default-size page of JSON-escaped names and answers nil params with a prefix`() =
        runTest {
            // JSON writes each control character as a six-byte escape, so each name takes about 6 KiB.
            val escaped = Char(1).toString().repeat(SealStoreMethods.MAX_NAME_BYTES - 3)
            repeat(SealStoreMethods.DEFAULT_PAGE_SIZE) { store.put("%03d".format(it) + escaped, secret.copyOf()) }

            val refused = call("SealStoreList", """{"page":1}""")
            val response = call("SealStoreList")

            assertEquals(ErrorCodes.INVALID_PARAMS, refused.code())
            assertFitsFrame(response)
            val result = response.ok()
            val names = result.getJSONArray("names").strings()
            assertTrue(names.size in 1 until SealStoreMethods.DEFAULT_PAGE_SIZE)
            assertEquals(store.list().take(names.size), names)
            assertEquals(SealStoreMethods.DEFAULT_PAGE_SIZE, result.getInt("total"))
            assertTrue(result.getBoolean("has_more"))
        }

    @Test
    fun `SealStoreList with a negative or non-integer page is invalid params`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("SealStoreList", """{"page":-1}""").code())
        assertEquals(ErrorCodes.INVALID_PARAMS, call("SealStoreList", """{"page_size":"ten"}""").code())
    }

    @Test
    fun `SealStoreList failing in storage is an internal error that leaks nothing`() = runTest {
        val response = call("SealStoreList", on = failingMethods())

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.code())
        assertFalse(response.error!!.message.contains("secret-name"))
    }

    // -------------------------------------------------------------------------
    // SealStoreReseal
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreReseal re-encrypts the secret in place and answers an empty result`() = runTest {
        putSecret("disk-key")

        val result = call("SealStoreReseal", """{"name":"disk-key"}""").ok()

        assertEquals(0, result.length())
        verify(exactly = 2) { cipher.encrypt(any()) }
        assertArrayEquals(secret, store.get("disk-key"))
    }

    @Test
    fun `SealStoreReseal of an unknown name is not found`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreReseal", """{"name":"nope"}""").code())
    }

    // -------------------------------------------------------------------------
    // SealStoreStatus
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreStatus answers every SealStoreStatusResponse field`() = runTest {
        putSecret("disk-key")

        val result = call("SealStoreStatus").ok()

        assertTrue(result.getBoolean("available"))
        assertEquals("android-keystore", result.getString("sealer_id"))
        assertEquals(1, result.getInt("secret_count"))
        assertEquals("disk-key", result.getJSONArray("secret_names").getString(0))
    }

    @Test
    fun `SealStoreStatus of an empty store omits secret_names`() = runTest {
        val result = call("SealStoreStatus").ok()

        assertEquals(0, result.getInt("secret_count"))
        assertFalse(result.has("secret_names"))
    }

    @Test
    fun `SealStoreStatus with many names stays within the frame and counts every secret`() = runTest {
        repeat(100) { putSecret(longName(it)) }

        val response = call("SealStoreStatus")
        val result = response.ok()

        assertFitsFrame(response)
        assertEquals(100, result.getInt("secret_count"))
        val names = result.getJSONArray("secret_names").strings()
        assertTrue(names.size in 1 until 100)
        assertEquals(store.list().take(names.size), names)
        assertTrue("one more name would not fit", nextNameOverflows(result, store.list()[names.size]))
    }

    @Test
    fun `SealStoreStatus failing in storage is an internal error`() = runTest {
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreStatus", on = failingMethods()).code())
    }

    private suspend fun listFailure(on: SealStore): Throwable? = runCatching { on.list() }.exceptionOrNull()

    @Test
    fun `a store that was never written lists empty and is available`() = runTest {
        val absent = SealStore(File(tmp.root, "never_written"), cipher)

        assertEquals(emptyList<String>(), absent.list())
        val status = call("SealStoreStatus", on = SealStoreMethods(absent)).ok()
        assertTrue(status.getBoolean("available"))
        assertEquals(0, status.getInt("secret_count"))
    }

    @Test
    fun `a store path that is not a directory is an internal error, never an empty store`() = runTest {
        // A regular file where the store's directory belongs: enumerating it
        // and looking a secret up in it fail with an I/O error, even as root.
        val broken = SealStore(tmp.newFile("seal_store_file"), cipher)
        val on = SealStoreMethods(broken)

        assertTrue(listFailure(broken) is SealStoreUnreadableException)
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreList", on = on).code())
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreStatus", on = on).code())
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreGet", """{"name":"disk-key"}""", on = on).code())
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreReseal", """{"name":"disk-key"}""", on = on).code())
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreDelete", """{"name":"disk-key"}""", on = on).code())
    }

    @Test
    fun `a store directory the process may not read is an internal error, never an empty store`() = runTest {
        putSecret("disk-key")
        assertTrue(dir.setReadable(false, false))
        try {
            // Root reads it regardless; the store-on-a-file case covers root.
            assumeFalse("running as root: permission bits are not enforced", dir.canRead())

            assertTrue(listFailure(store) is SealStoreUnreadableException)
            assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreList").code())
            assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreStatus").code())
        } finally {
            dir.setReadable(true, false)
        }
    }

    @Test
    fun `a store directory the process may not search hides no secret and finds none missing`() = runTest {
        putSecret("disk-key")
        val sealed = dir.listFiles()!!.single { it.name.endsWith(".sealed") }
        // Its names still enumerate, but every lookup inside it fails, where
        // File.exists() answers false.
        assertTrue(dir.setExecutable(false, false))
        try {
            // Root searches it regardless; the store-on-a-file case covers root.
            assumeFalse("running as root: permission bits are not enforced", sealed.exists())

            assertTrue(listFailure(store) is SealStoreUnreadableException)
            assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreList").code())
            assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreStatus").code())
            assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreGet", """{"name":"disk-key"}""").code())
            assertEquals(ErrorCodes.INTERNAL_ERROR, call("SealStoreReseal", """{"name":"disk-key"}""").code())
        } finally {
            dir.setExecutable(true, false)
        }
    }
}
