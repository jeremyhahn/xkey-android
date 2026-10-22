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

import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.password.PassphraseHasher
import com.automatethethings.xkey.password.PasswordDao
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordVault
import com.automatethethings.xkey.password.PasswordVaultFactorRecord
import com.automatethethings.xkey.password.PasswordVaultFactorStore
import com.automatethethings.xkey.password.VaultUnlockAttemptStore
import com.automatethethings.xkey.password.VaultUnlockLimits
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import com.automatethethings.xkey.storage.SealStore
import com.automatethethings.xkey.transport.StreamMessageFraming
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException
import java.security.MessageDigest
import java.util.Base64

/**
 * The USB wire contract with go-xkms (`pkg/api/transport/types.go` and the
 * `pkg/pairing` JSON-RPC client) for the fifteen password- and seal-store
 * methods it sends.
 *
 * Each request is the bytes go-xkms' `json.Marshal` writes for its request
 * struct, written out by hand: fields in struct order, `omitempty` fields
 * dropped, and no `params` key for a nil-params call. It enters through
 * [UsbAccessoryServer.handlePlaintext], the dispatch the USB message loop
 * runs each decrypted message through, on a server wired as `XKeyGattService`
 * wires it. Pairing is not enforced here: that gate runs before dispatch and
 * is tested on its own.
 *
 * Each `result` must decode as Go's `encoding/json` decodes it into the
 * response struct ([assertDecodes]): every field present has its Go type,
 * never JSON null, and every field without `omitempty` is present. Each
 * `error` must decode as `{"code":int,"message":string}`.
 */
class UsbWireContractTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val marker: Byte = 0x7f
    private val createdAt = 1_700_000_000_000L
    private val createdAtIso = "2023-11-14T22:13:20Z"

    private lateinit var dao: InMemoryPasswordDao
    private lateinit var cipher: KeystoreAeadCipher
    private lateinit var vault: PasswordVault
    private lateinit var handler: RequestHandler
    private lateinit var server: UsbAccessoryServer
    private var nextId = 1L

    private class InMemoryPasswordDao : PasswordDao {
        val rows = linkedMapOf<String, PasswordEntity>()
        var failing = false
        private var rowId = 0L

        override suspend fun insert(password: PasswordEntity): Long {
            val id = if (password.id != 0L) password.id else ++rowId
            rows[password.passwordId] = password.copy(id = id)
            return id
        }
        override suspend fun insertIfAbsent(password: PasswordEntity): Long =
            if (rows.containsKey(password.passwordId)) -1 else insert(password.copy(id = 0))
        override suspend fun update(password: PasswordEntity): Int {
            if (rows[password.passwordId]?.id != password.id) return 0
            rows[password.passwordId] = password
            return 1
        }
        override suspend fun updateFieldsIfUnchanged(
            id: Long,
            expectedPasswordEncrypted: ByteArray,
            expectedName: String,
            expectedTitle: String?,
            expectedUsername: String?,
            expectedUrl: String?,
            expectedNotes: String?,
            expectedFolderPath: String?,
            expectedSource: String,
            expectedCreatedAt: Long,
            expectedUpdatedAt: Long,
            expectedExpiresAt: String?,
            expectedShared: Boolean,
            expectedTenantId: String,
            name: String,
            title: String?,
            username: String?,
            passwordEncrypted: ByteArray,
            url: String?,
            notes: String?,
            folderPath: String?,
            source: String,
            expiresAt: String?,
            updatedAt: Long
        ): Int {
            val current = rows.values.firstOrNull {
                it.id == id && it.passwordEncrypted.contentEquals(expectedPasswordEncrypted) &&
                    it.name == expectedName && it.title == expectedTitle && it.username == expectedUsername &&
                    it.url == expectedUrl && it.notes == expectedNotes && it.folderPath == expectedFolderPath &&
                    it.source == expectedSource && it.createdAt == expectedCreatedAt &&
                    it.updatedAt == expectedUpdatedAt && it.expiresAt == expectedExpiresAt &&
                    it.shared == expectedShared && it.tenantId == expectedTenantId
            } ?: return 0
            rows[current.passwordId] = current.copy(
                name = name, title = title, username = username, passwordEncrypted = passwordEncrypted,
                url = url, notes = notes, folderPath = folderPath, source = source, expiresAt = expiresAt,
                updatedAt = updatedAt
            )
            return 1
        }
        override fun observeAll(): Flow<List<PasswordEntity>> = flowOf(rows.values.toList())
        override suspend fun getAll(): List<PasswordEntity> {
            if (failing) throw IllegalStateException("disk full: secret-entry-content")
            return rows.values.sortedWith(compareBy<PasswordEntity>({ it.name }, { it.username }))
        }
        override suspend fun getByPasswordId(passwordId: String): PasswordEntity? = rows[passwordId]
        override suspend fun getByPasswordIdInTenant(passwordId: String, tenantId: String): PasswordEntity? =
            rows[passwordId]?.takeIf { it.tenantId == tenantId }
        override suspend fun getForListing(tenantId: String, shared: Boolean?, folderPath: String?): List<PasswordEntity> =
            getAll().filter {
                it.tenantId == tenantId && (shared == null || it.shared == shared) &&
                    (folderPath == null || it.folderPath == folderPath)
            }
        override suspend fun getBySource(source: String): List<PasswordEntity> =
            rows.values.filter { it.source == source }
        override suspend fun deleteByPasswordId(passwordId: String): Int =
            if (rows.remove(passwordId) != null) 1 else 0
        override suspend fun deleteByPasswordIdInTenant(passwordId: String, tenantId: String): Int =
            if (rows[passwordId]?.tenantId == tenantId) deleteByPasswordId(passwordId) else 0
        override suspend fun count(): Int {
            if (failing) throw IllegalStateException("disk full: secret-entry-content")
            return rows.size
        }
        override fun observeCount(): Flow<Int> = flowOf(rows.size)
    }

    private class InMemoryFactorStore : PasswordVaultFactorStore {
        val records = mutableListOf<PasswordVaultFactorRecord>()
        override suspend fun list(): List<PasswordVaultFactorRecord> = records.toList()
        override suspend fun add(record: PasswordVaultFactorRecord) {
            records += record
        }
    }

    private class InMemoryAttemptStore : VaultUnlockAttemptStore {
        var counter = VaultUnlockAttempts()
        override suspend fun limits(): VaultUnlockLimits =
            PinSettingsData().let { VaultUnlockLimits(it.maxPinAttempts, it.lockoutDurationSeconds) }
        override suspend fun read(): VaultUnlockAttempts = counter
        override suspend fun write(attempts: VaultUnlockAttempts) {
            counter = attempts
        }
    }

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

        cipher = mockk()
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
        dao = InMemoryPasswordDao()
        vault = PasswordVault(InMemoryFactorStore(), InMemoryAttemptStore(), PassphraseHasher { passphrase, salt ->
            MessageDigest.getInstance("SHA-256").run {
                update(salt)
                digest(passphrase.toByteArray(Charsets.UTF_8))
            }
        })
        handler = mockk(relaxed = true)
        // As XKeyGattService wires USB: the password store, then the seal store.
        server = usbServer(
            PasswordStoreMethods(PasswordRepository(dao, cipher), vault, clock = { createdAt }),
            SealStoreMethods(SealStore(tmp.newFolder("seal_store"), cipher))
        )
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun usbServer(vararg storeMethods: TransportMethods): UsbAccessoryServer =
        UsbAccessoryServer(requestHandler = handler, storeMethods = storeMethods.toList())

    /**
     * Sends go-xkms' `Request` for [method] with [params] as `json.Marshal`
     * writes it, `params` omitted when null, and returns the response
     * envelope, which must echo the id and carry exactly one of `result` and
     * `error`.
     */
    private suspend fun call(method: String, params: String? = null, on: UsbAccessoryServer = server): JSONObject {
        val id = nextId++
        val paramsField = if (params == null) "" else ""","params":$params"""
        val request = """{"jsonrpc":"2.0","id":$id,"method":"$method"$paramsField}"""
        val answer = on.handlePlaintext(request.toByteArray(Charsets.UTF_8))
        assertNotNull("$method was not answered", answer)
        val envelope = JSONObject(String(answer!!, Charsets.UTF_8))
        assertTrue("$method: id must be an integer", envelope.get("id").isGoInt())
        assertEquals("$method: id must echo the request's", id, envelope.getLong("id"))
        assertTrue("$method: exactly one of result and error", envelope.has("result") != envelope.has("error"))
        return envelope
    }

    /** The envelope's `result`, which must decode as the Go struct [struct] with [fields]. */
    private fun JSONObject.decodedResult(struct: String, fields: Map<String, GoField>): JSONObject {
        assertFalse("$struct: unexpected error ${opt("error")}", has("error"))
        val result = get("result")
        assertTrue("$struct: result must be an object", result is JSONObject)
        assertDecodes(struct, fields, result as JSONObject)
        return result
    }

    /** A success whose `result` go-xkms ignores, which must still be an object. */
    private fun JSONObject.assertIgnoredResult(method: String) {
        assertFalse("$method: unexpected error ${opt("error")}", has("error"))
        assertTrue("$method: result must be an object", get("result") is JSONObject)
    }

    /** The envelope's `error`, which must decode as go-xkms' RPC error; returns its code. */
    private fun JSONObject.errorCode(): Int {
        assertFalse("unexpected result ${opt("result")}", has("result"))
        val error = get("error")
        assertTrue("error must be an object", error is JSONObject)
        assertDecodes("RPCError", RPC_ERROR, error as JSONObject)
        return error.getInt("code")
    }

    private suspend fun add(params: String): String =
        call("PasswordAdd", params).decodedResult("PasswordAddResponse", PASSWORD_ADD_RESPONSE).getString("id")

    private suspend fun getEntry(id: String): JSONObject =
        call("PasswordGet", """{"id":"$id"}""").decodedResult("PasswordGetResponse", PASSWORD_GET_RESPONSE)

    private suspend fun status(): JSONObject =
        call("PasswordStoreStatus").decodedResult("PasswordStoreStatusResponse", PASSWORD_STORE_STATUS_RESPONSE)

    private suspend fun generate(params: String): String =
        call("PasswordGenerate", params).decodedResult("PasswordGenerateResponse", PASSWORD_GENERATE_RESPONSE)
            .getString("password")

    private suspend fun put(name: String, secret: ByteArray) =
        call("SealStorePut", """{"name":"$name","secret":"${Base64.getEncoder().encodeToString(secret)}"}""")
            .assertIgnoredResult("SealStorePut")

    private suspend fun unseal(name: String): ByteArray {
        val result = call("SealStoreGet", """{"name":"$name"}""")
            .decodedResult("SealStoreGetResponse", SEAL_STORE_GET_RESPONSE)
        assertEquals(name, result.getString("name"))
        return Base64.getDecoder().decode(result.getString("secret"))
    }

    private fun JSONArray.itemNames(): List<String> = (0 until length()).map { getJSONObject(it).getString("name") }

    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }

    // -------------------------------------------------------------------------
    // Routing
    // -------------------------------------------------------------------------

    @Test
    fun `every store method go-xkms sends is answered on USB by the store families, never the shared handler`() = runTest {
        for (method in GO_XKMS_METHODS) call(method, "{}")

        coVerify(exactly = 0) { handler.handleRawRequest(any()) }
    }

    // -------------------------------------------------------------------------
    // PasswordAdd
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordAdd with every PasswordAddRequest field the phone stores answers a PasswordAddResponse`() = runTest {
        val result = call("PasswordAdd", FULL_ADD).decodedResult("PasswordAddResponse", PASSWORD_ADD_RESPONSE)

        assertTrue(result.getString("id").isNotEmpty())
        assertEquals("GitHub", result.getString("name"))
        assertEquals(createdAtIso, result.getString("created_at"))
    }

    @Test
    fun `PasswordAdd with only the fields json-Marshal never drops answers a PasswordAddResponse`() = runTest {
        val result = call("PasswordAdd", """{"name":"GitHub","password":"hunter2"}""")
            .decodedResult("PasswordAddResponse", PASSWORD_ADD_RESPONSE)

        assertEquals("GitHub", result.getString("name"))
    }

    @Test
    fun `PasswordAdd with an unset name answers an RPC error`() = runTest {
        // name has no omitempty: an unset one is marshalled as the empty string.
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordAdd", """{"name":"","password":"hunter2"}""").errorCode())
        assertTrue(dao.rows.isEmpty())
    }

    // -------------------------------------------------------------------------
    // PasswordGet
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordGet answers a PasswordGetResponse that omits the policy fields left unset`() = runTest {
        val id = add(FULL_ADD)

        val result = call("PasswordGet", """{"id":"$id"}""")
            .decodedResult("PasswordGetResponse", PASSWORD_GET_RESPONSE)

        assertEquals(id, result.getString("id"))
        assertEquals("GitHub", result.getString("name"))
        assertEquals("Work", result.getString("title"))
        assertEquals("octo", result.getString("username"))
        assertEquals("hunter2", result.getString("password"))
        assertEquals("https://github.com", result.getString("url"))
        assertEquals("recovery codes in the safe", result.getString("notes"))
        assertEquals("dev", result.getString("folder_path"))
        assertEquals(createdAtIso, result.getString("created_at"))
        assertEquals(createdAtIso, result.getString("updated_at"))
        assertTrue(result.getBoolean("encrypted"))
        // No expiry and not shared: omitted, never null. tenant_id is never answered.
        assertFalse(result.has("expires_at"))
        assertFalse(result.has("tenant_id"))
        assertFalse(result.has("shared"))
    }

    @Test
    fun `PasswordGet of an entry with no optional field omits every empty omitempty field`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2"}""")

        val result = getEntry(id)

        assertEquals(
            setOf("id", "name", "password", "created_at", "updated_at", "encrypted"),
            result.keys().asSequence().toSet()
        )
    }

    @Test
    fun `PasswordGet of an unknown id answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("PasswordGet", """{"id":"missing"}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // PasswordList
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordList with the zero PasswordListRequest answers a PasswordListResponse`() = runTest {
        add(FULL_ADD)
        add("""{"name":"Alpha","password":"pw"}""")

        // Every PasswordListRequest field is omitempty, so the zero request marshals to {}.
        val result = call("PasswordList", "{}").decodedResult("PasswordListResponse", PASSWORD_LIST_RESPONSE)

        val passwords = result.getJSONArray("passwords")
        assertEquals(listOf("Alpha", "GitHub"), passwords.itemNames())
        for (i in 0 until passwords.length()) assertFalse(passwords.getJSONObject(i).has("password"))
        assertEquals(0, result.getInt("page"))
        assertEquals(2, result.getInt("total"))
        assertFalse(result.getBoolean("has_more"))
    }

    @Test
    fun `PasswordList with every PasswordListRequest field the phone honours answers the requested page`() = runTest {
        add("""{"name":"a","password":"pw","folder_path":"dev"}""")
        add("""{"name":"b","password":"pw","folder_path":"dev"}""")
        add("""{"name":"c","password":"pw","folder_path":"ops"}""")

        val result = call(
            "PasswordList",
            """{"folder_path":"dev","page":1,"page_size":10,"sort_field":"name","sort_order":1}"""
        ).decodedResult("PasswordListResponse", PASSWORD_LIST_RESPONSE)

        assertEquals(listOf("b", "a"), result.getJSONArray("passwords").itemNames())
        assertEquals(1, result.getInt("page"))
        assertEquals(10, result.getInt("page_size"))
        assertEquals(2, result.getInt("total"))
        assertFalse(result.getBoolean("has_more"))
    }

    @Test
    fun `PasswordList items carry created_at, updated_at and encrypted, the minimal form included`() = runTest {
        val big = add("""{"name":"aaa","password":"pw"}""")
        add("""{"name":"bbb","password":"pw"}""")
        // Notes over a whole frame, as a writer before the size limit could store them.
        dao.rows[big] = dao.rows.getValue(big).copy(notes = "n".repeat(StreamMessageFraming.MAX_MESSAGE_SIZE))

        val result = call("PasswordList", "{}").decodedResult("PasswordListResponse", PASSWORD_LIST_RESPONSE)

        val minimal = result.getJSONArray("passwords").getJSONObject(0)
        assertEquals(big, minimal.getString("id"))
        assertEquals(
            setOf("id", "name", "created_at", "updated_at", "encrypted"),
            minimal.keys().asSequence().toSet()
        )
    }

    @Test
    fun `PasswordList on a locked store answers an RPC error`() = runTest {
        vault.enrollPassphrase("correct horse")

        assertEquals(ErrorCodes.PASSWORD_STORE_LOCKED, call("PasswordList", "{}").errorCode())
    }

    // -------------------------------------------------------------------------
    // PasswordUpdate
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordUpdate with go-xkms pointer fields answers a valid response and applies them`() = runTest {
        val id = add(FULL_ADD)

        // *string fields: nil is omitted, a pointer to "" clears the field.
        call("PasswordUpdate", """{"id":"$id","title":"","password":"hunter3","notes":"rotated"}""")
            .assertIgnoredResult("PasswordUpdate")

        val entry = getEntry(id)
        assertFalse(entry.has("title"))
        assertEquals("octo", entry.getString("username"))
        assertEquals("hunter3", entry.getString("password"))
        assertEquals("rotated", entry.getString("notes"))
    }

    @Test
    fun `PasswordUpdate of an unknown id answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("PasswordUpdate", """{"id":"missing","notes":"x"}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // PasswordDelete
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordDelete answers a valid response`() = runTest {
        val id = add(FULL_ADD)

        call("PasswordDelete", """{"id":"$id"}""").assertIgnoredResult("PasswordDelete")

        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun `PasswordDelete with an unset id answers an RPC error`() = runTest {
        // id has no omitempty: an unset one is marshalled as the empty string.
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordDelete", """{"id":""}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // Policy fields: expires_at, shared, tenant_id and scope
    // -------------------------------------------------------------------------

    /** go-xkms' request for [method] on entry [id], with [field] set to the raw JSON [value] or omitted when null. */
    private fun policyRequest(method: String, id: String, field: String, value: String?): String {
        val extra = if (value == null) "" else ""","$field":$value"""
        return when (method) {
            "PasswordAdd" -> """{"name":"GitHub","password":"hunter2"$extra}"""
            "PasswordList" -> "{${extra.removePrefix(",")}}"
            "PasswordUpdate" -> """{"id":"$id","notes":"rotated"$extra}"""
            else -> """{"id":"$id"$extra}"""
        }
    }

    /** Every method carrying [field] answers a result with it at each of its [defaults]. */
    private suspend fun assertDefaultsAccepted(field: String, defaults: List<String?>) {
        for (method in POLICY_METHODS.getValue(field)) {
            for (value in defaults) {
                val id = add("""{"name":"Base","password":"pw"}""")
                call(method, policyRequest(method, id, field, value)).assertIgnoredResult("$method with $field=$value")
            }
        }
    }

    /** [method] with [params] answers INVALID_PARAMS with [message] and writes nothing. */
    private suspend fun assertInvalid(method: String, params: String, message: String) {
        val before = dao.rows.toMap()

        val envelope = call(method, params)

        assertEquals("$method $params", ErrorCodes.INVALID_PARAMS, envelope.errorCode())
        assertEquals(message, envelope.getJSONObject("error").getString("message"))
        assertEquals("$method $params must write nothing", before, dao.rows.toMap())
    }

    /** PasswordGet of [id] in [tenant], as go-xkms sends it. */
    private suspend fun getEntry(id: String, tenant: String): JSONObject =
        call("PasswordGet", """{"id":"$id","tenant_id":"$tenant"}""")
            .decodedResult("PasswordGetResponse", PASSWORD_GET_RESPONSE)

    /** PasswordList with [params], as the names of the page it answers. */
    private suspend fun listNames(params: String): List<String> =
        call("PasswordList", params).decodedResult("PasswordListResponse", PASSWORD_LIST_RESPONSE)
            .getJSONArray("passwords").itemNames()

    @Test
    fun `expires_at unset, null or empty is accepted on PasswordAdd and PasswordUpdate`() = runTest {
        // ExpiresAt string on PasswordAddRequest; *string on PasswordUpdateRequest, where "" clears an expiry.
        assertDefaultsAccepted("expires_at", listOf(null, "null", "\"\""))
    }

    @Test
    fun `shared unset, null or false is accepted on PasswordAdd`() = runTest {
        assertDefaultsAccepted("shared", listOf(null, "null", "false"))
    }

    @Test
    fun `tenant_id unset, null or empty is accepted on every password request`() = runTest {
        assertDefaultsAccepted("tenant_id", listOf(null, "null", "\"\""))
    }

    @Test
    fun `scope unset, null or empty is accepted on PasswordList`() = runTest {
        assertDefaultsAccepted("scope", listOf(null, "null", "\"\""))
    }

    @Test
    fun `the default forms store no expiry, a personal entry and the default tenant`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2","expires_at":"","shared":false,"tenant_id":""}""")

        val row = dao.rows.getValue(id)
        assertEquals(null, row.expiresAt)
        assertFalse(row.shared)
        assertEquals("", row.tenantId)
        // The default tenant's entry is the one a request without tenant_id reaches.
        assertEquals("GitHub", getEntry(id).getString("name"))
    }

    @Test
    fun `PasswordAdd stores expires_at and PasswordGet answers it`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2","expires_at":"2030-01-01T00:00:00Z"}""")

        assertEquals("2030-01-01T00:00:00Z", getEntry(id).getString("expires_at"))
    }

    @Test
    fun `PasswordAdd stores shared and PasswordGet answers it`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2","shared":true}""")

        assertTrue(getEntry(id).getBoolean("shared"))
        assertTrue(dao.rows.getValue(id).shared)
    }

    @Test
    fun `PasswordAdd stores tenant_id and PasswordGet in that tenant answers the entry without it`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2","tenant_id":"t1","shared":true}""")

        val result = getEntry(id, "t1")

        assertEquals("t1", dao.rows.getValue(id).tenantId)
        assertEquals("hunter2", result.getString("password"))
        assertTrue(result.getBoolean("shared"))
        // tenant_id is a request filter: never answered.
        assertFalse(result.has("tenant_id"))
    }

    @Test
    fun `expires_at is stored as the UTC instant it names`() = runTest {
        val offset = add("""{"name":"a","password":"pw","expires_at":"2027-01-02T05:04:05+02:00"}""")
        val fraction = add("""{"name":"b","password":"pw","expires_at":"2027-01-02t03:04:05.5z"}""")

        assertEquals("2027-01-02T03:04:05Z", dao.rows.getValue(offset).expiresAt)
        assertEquals("2027-01-02T03:04:05.500Z", getEntry(fraction).getString("expires_at"))
    }

    @Test
    fun `an expires_at that is not an RFC 3339 date-time is refused with INVALID_PARAMS and nothing written`() = runTest {
        val id = add("""{"name":"Base","password":"pw"}""")
        val message = "expires_at must be an RFC 3339 date-time"

        for (value in listOf("tomorrow", "2030-01-01", "2030-01-01T00:00:00", "2030-13-01T00:00:00Z", "+10000-01-01T00:00:00Z")) {
            assertInvalid("PasswordAdd", """{"name":"GitHub","password":"hunter2","expires_at":"$value"}""", message)
            assertInvalid("PasswordUpdate", """{"id":"$id","expires_at":"$value"}""", message)
        }
        assertInvalid("PasswordAdd", """{"name":"GitHub","password":"hunter2","expires_at":5}""", "expires_at must be a string")
    }

    @Test
    fun `PasswordUpdate sets, keeps and clears expires_at`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2"}""")

        call("PasswordUpdate", """{"id":"$id","expires_at":"2031-06-01T12:00:00-04:00"}""").assertIgnoredResult("set")
        assertEquals("2031-06-01T16:00:00Z", getEntry(id).getString("expires_at"))

        // A nil *string is omitted: the expiry stays, absent or JSON null alike.
        call("PasswordUpdate", """{"id":"$id","notes":"rotated"}""").assertIgnoredResult("absent")
        call("PasswordUpdate", """{"id":"$id","expires_at":null}""").assertIgnoredResult("null")
        assertEquals("2031-06-01T16:00:00Z", getEntry(id).getString("expires_at"))

        call("PasswordUpdate", """{"id":"$id","expires_at":""}""").assertIgnoredResult("clear")
        assertFalse(getEntry(id).has("expires_at"))
    }

    @Test
    fun `PasswordUpdate in the entry's tenant keeps its tenant and sharing`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2","tenant_id":"t1","shared":true}""")

        call("PasswordUpdate", """{"id":"$id","tenant_id":"t1","notes":"rotated"}""").assertIgnoredResult("update")

        val row = dao.rows.getValue(id)
        assertEquals("t1", row.tenantId)
        assertTrue(row.shared)
        assertEquals("rotated", getEntry(id, "t1").getString("notes"))
    }

    @Test
    fun `another tenant's entry is not found by PasswordGet, PasswordUpdate or PasswordDelete`() = runTest {
        val id = add("""{"name":"GitHub","password":"hunter2","tenant_id":"t1"}""")
        val before = dao.rows.toMap()

        for (tenant in listOf(null, "", "t2")) {
            val field = if (tenant == null) "" else ""","tenant_id":"$tenant""""
            for (request in listOf(
                "PasswordGet" to """{"id":"$id"$field}""",
                "PasswordUpdate" to """{"id":"$id","notes":"x"$field}""",
                "PasswordDelete" to """{"id":"$id"$field}"""
            )) {
                assertEquals("${request.first} in $tenant", ErrorCodes.KEY_NOT_FOUND, call(request.first, request.second).errorCode())
            }
        }
        assertEquals(before, dao.rows.toMap())

        call("PasswordDelete", """{"id":"$id","tenant_id":"t1"}""").assertIgnoredResult("PasswordDelete in t1")
        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun `PasswordList answers only the requested tenant's entries`() = runTest {
        add("""{"name":"a","password":"pw"}""")
        add("""{"name":"b","password":"pw","tenant_id":"t1"}""")
        add("""{"name":"c","password":"pw","tenant_id":"t2"}""")

        assertEquals(listOf("a"), listNames("{}"))
        assertEquals(listOf("a"), listNames("""{"tenant_id":""}"""))
        assertEquals(listOf("b"), listNames("""{"tenant_id":"t1"}"""))
    }

    @Test
    fun `PasswordList filters by scope`() = runTest {
        add("""{"name":"mine","password":"pw","tenant_id":"t1"}""")
        add("""{"name":"ours","password":"pw","tenant_id":"t1","shared":true}""")

        assertEquals(listOf("mine"), listNames("""{"tenant_id":"t1","scope":"personal"}"""))
        assertEquals(listOf("ours"), listNames("""{"tenant_id":"t1","scope":"shared"}"""))
        assertEquals(listOf("mine", "ours"), listNames("""{"tenant_id":"t1","scope":"all"}"""))
        assertEquals(listOf("mine", "ours"), listNames("""{"tenant_id":"t1"}"""))
    }

    @Test
    fun `PasswordList with an unknown scope is refused with INVALID_PARAMS`() = runTest {
        for (scope in listOf("\"mine\"", "\"Shared\"", "\"ALL\"")) {
            assertInvalid("PasswordList", """{"scope":$scope}""", "scope must be one of personal, shared, all")
        }
        assertInvalid("PasswordList", """{"scope":1}""", "scope must be a string")
    }

    @Test
    fun `PasswordList pages are full under a scope filter`() = runTest {
        for (i in 1..3) {
            add("""{"name":"p$i","password":"pw"}""")
            add("""{"name":"s$i","password":"pw","shared":true}""")
        }

        // Pages are 1-based; page 0 (or none) is the whole listing, whatever page_size says.
        val result = call("PasswordList", """{"scope":"shared","page":1,"page_size":2}""")
            .decodedResult("PasswordListResponse", PASSWORD_LIST_RESPONSE)

        assertEquals(listOf("s1", "s2"), result.getJSONArray("passwords").itemNames())
        assertEquals(3, result.getInt("total"))
        assertTrue(result.getBoolean("has_more"))
        assertEquals(listOf("s3"), listNames("""{"scope":"shared","page":2,"page_size":2}"""))
    }

    @Test
    fun `PasswordList items carry expires_at and shared but never tenant_id`() = runTest {
        add("""{"name":"a","password":"pw","tenant_id":"t1","shared":true,"expires_at":"2030-01-01T00:00:00Z"}""")

        val item = call("PasswordList", """{"tenant_id":"t1"}""")
            .decodedResult("PasswordListResponse", PASSWORD_LIST_RESPONSE)
            .getJSONArray("passwords").getJSONObject(0)

        assertEquals("2030-01-01T00:00:00Z", item.getString("expires_at"))
        assertTrue(item.getBoolean("shared"))
        assertFalse(item.has("tenant_id"))
    }

    @Test
    fun `PasswordAdd's id finds the entry for PasswordGet, PasswordUpdate and PasswordDelete`() = runTest {
        val id = add("""{"name":"GitHub","username":"octo","password":"hunter2"}""")
        assertEquals("hunter2", getEntry(id).getString("password"))

        call("PasswordUpdate", """{"id":"$id","username":"hubot"}""").assertIgnoredResult("PasswordUpdate")
        assertEquals("hubot", getEntry(id).getString("username"))

        call("PasswordDelete", """{"id":"$id"}""").assertIgnoredResult("PasswordDelete")
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("PasswordGet", """{"id":"$id"}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // PasswordStoreUnlock and PasswordStoreLock
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordStoreUnlock with a passphrase credential answers a valid response`() = runTest {
        vault.enrollPassphrase("correct horse")

        // PasswordVaultCredential's other fields are omitempty and dropped.
        call("PasswordStoreUnlock", UNLOCK).assertIgnoredResult("PasswordStoreUnlock")

        assertFalse(status().getBoolean("is_locked"))
    }

    @Test
    fun `PasswordStoreUnlock with a wrong passphrase answers an RPC error`() = runTest {
        vault.enrollPassphrase("correct horse")

        val code = call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"wrong"}""").errorCode()

        assertEquals(ErrorCodes.VAULT_CREDENTIAL_REJECTED, code)
    }

    @Test
    fun `PasswordStoreLock accepts absent, null and empty params`() = runTest {
        vault.enrollPassphrase("correct horse")

        for (params in NIL_PARAMS) {
            call("PasswordStoreUnlock", UNLOCK).assertIgnoredResult("PasswordStoreUnlock")
            call("PasswordStoreLock", params).assertIgnoredResult("PasswordStoreLock")
            assertTrue("params $params", status().getBoolean("is_locked"))
        }
    }

    @Test
    fun `PasswordStoreLock before any factor is enrolled answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.VAULT_NOT_INITIALIZED, call("PasswordStoreLock").errorCode())
    }

    // -------------------------------------------------------------------------
    // PasswordStoreStatus
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordStoreStatus accepts absent, null and empty params and answers a PasswordStoreStatusResponse`() = runTest {
        add(FULL_ADD)

        for (params in NIL_PARAMS) {
            val result = call("PasswordStoreStatus", params)
                .decodedResult("PasswordStoreStatusResponse", PASSWORD_STORE_STATUS_RESPONSE)

            assertEquals("params $params", "local", result.getString("access_mode"))
            assertFalse(result.getBoolean("is_locked"))
            assertEquals(1, result.getInt("password_count"))
        }
    }

    @Test
    fun `PasswordStoreStatus failing in storage answers an RPC error`() = runTest {
        dao.failing = true

        assertEquals(ErrorCodes.INTERNAL_ERROR, call("PasswordStoreStatus").errorCode())
    }

    // -------------------------------------------------------------------------
    // PasswordGenerate
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordGenerate with the zero PasswordGenerateRequest answers a default-length password`() = runTest {
        // length and the four flags have no omitempty, so the zero request still sends them.
        val password = generate("""{"length":0,"upper":false,"lower":false,"digits":false,"symbols":false}""")

        assertEquals(PasswordStoreMethods.DEFAULT_GENERATE_LENGTH, password.length)
    }

    @Test
    fun `PasswordGenerate honours length and the flags`() = runTest {
        val password = generate("""{"length":40,"upper":false,"lower":true,"digits":true,"symbols":false}""")

        assertEquals(40, password.length)
        assertTrue(password, password.all { it in 'a'..'z' || it in '0'..'9' })
        assertTrue(password, password.any { it in 'a'..'z' })
        assertTrue(password, password.any { it in '0'..'9' })
    }

    @Test
    fun `PasswordGenerate honours charset over the flags`() = runTest {
        val password = generate(
            """{"length":16,"upper":true,"lower":false,"digits":false,"symbols":false,"charset":"xyz"}"""
        )

        assertEquals(16, password.length)
        assertTrue(password, password.all { it in "xyz" })
    }

    @Test
    fun `PasswordGenerate past the longest length answers an RPC error`() = runTest {
        val tooLong = PasswordStoreMethods.MAX_GENERATE_LENGTH + 1

        val code = call(
            "PasswordGenerate",
            """{"length":$tooLong,"upper":false,"lower":false,"digits":false,"symbols":false}"""
        ).errorCode()

        assertEquals(ErrorCodes.INVALID_PARAMS, code)
    }

    // -------------------------------------------------------------------------
    // SealStorePut and SealStoreGet
    // -------------------------------------------------------------------------

    @Test
    fun `SealStorePut then SealStoreGet returns the same bytes through base64`() = runTest {
        // Every byte value, so the encoding carries + and / and padding.
        val secret = ByteArray(256) { it.toByte() }

        put("db-key", secret)

        assertArrayEquals(secret, unseal("db-key"))
    }

    @Test
    fun `SealStorePut with an unset name answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("SealStorePut", """{"name":"","secret":"AAECA/8="}""").errorCode())
    }

    @Test
    fun `SealStoreGet of an unknown name answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreGet", """{"name":"missing"}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // SealStoreDelete and SealStoreReseal
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreDelete answers a valid response`() = runTest {
        put("db-key", byteArrayOf(1, 2, 3))

        call("SealStoreDelete", """{"name":"db-key"}""").assertIgnoredResult("SealStoreDelete")

        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreGet", """{"name":"db-key"}""").errorCode())
    }

    @Test
    fun `SealStoreDelete of an unknown name answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreDelete", """{"name":"missing"}""").errorCode())
    }

    @Test
    fun `SealStoreReseal answers a valid response and keeps the secret`() = runTest {
        val secret = byteArrayOf(0, 1, 2, 3, -1)
        put("db-key", secret)

        call("SealStoreReseal", """{"name":"db-key"}""").assertIgnoredResult("SealStoreReseal")

        assertArrayEquals(secret, unseal("db-key"))
    }

    @Test
    fun `SealStoreReseal of an unknown name answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("SealStoreReseal", """{"name":"missing"}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // SealStoreList
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreList accepts absent, null and empty params and answers a SealStoreListResponse`() = runTest {
        put("b-key", byteArrayOf(1))
        put("a-key", byteArrayOf(2))

        for (params in NIL_PARAMS) {
            val result = call("SealStoreList", params).decodedResult("SealStoreListResponse", SEAL_STORE_LIST_RESPONSE)

            assertEquals("params $params", listOf("a-key", "b-key"), result.getJSONArray("names").strings())
            assertEquals(2, result.getInt("total"))
            assertFalse(result.getBoolean("has_more"))
        }
    }

    @Test
    fun `SealStoreList with a PageRequest answers the requested page`() = runTest {
        put("b-key", byteArrayOf(1))
        put("a-key", byteArrayOf(2))

        val result = call("SealStoreList", """{"page":1,"page_size":1}""")
            .decodedResult("SealStoreListResponse", SEAL_STORE_LIST_RESPONSE)

        assertEquals(listOf("a-key"), result.getJSONArray("names").strings())
        assertEquals(1, result.getInt("page"))
        assertEquals(1, result.getInt("page_size"))
        assertEquals(2, result.getInt("total"))
        assertTrue(result.getBoolean("has_more"))
    }

    @Test
    fun `SealStoreList with a negative page answers an RPC error`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("SealStoreList", """{"page":-1}""").errorCode())
    }

    // -------------------------------------------------------------------------
    // SealStoreStatus
    // -------------------------------------------------------------------------

    @Test
    fun `SealStoreStatus accepts absent, null and empty params and answers a SealStoreStatusResponse`() = runTest {
        put("b-key", byteArrayOf(1))
        put("a-key", byteArrayOf(2))

        for (params in NIL_PARAMS) {
            val result = call("SealStoreStatus", params)
                .decodedResult("SealStoreStatusResponse", SEAL_STORE_STATUS_RESPONSE)

            assertTrue("params $params", result.getBoolean("available"))
            assertEquals(SealStore.SEALER_ID, result.getString("sealer_id"))
            assertEquals(2, result.getInt("secret_count"))
            assertEquals(listOf("a-key", "b-key"), result.getJSONArray("secret_names").strings())
        }
    }

    @Test
    fun `SealStoreStatus of an empty store still answers available and secret_count`() = runTest {
        val result = call("SealStoreStatus").decodedResult("SealStoreStatusResponse", SEAL_STORE_STATUS_RESPONSE)

        assertTrue(result.getBoolean("available"))
        assertEquals(0, result.getInt("secret_count"))
    }

    @Test
    fun `SealStoreStatus failing in storage answers an RPC error`() = runTest {
        val broken = mockk<SealStore>()
        coEvery { broken.list() } throws IOException("disk full: secret-bytes")

        val response = call("SealStoreStatus", on = usbServer(SealStoreMethods(broken)))

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
    }
}

// -----------------------------------------------------------------------------
// go-xkms' requests and response structs
// -----------------------------------------------------------------------------

/** Every store method go-xkms sends over USB. `PasswordStoreSetAccessMode` is never sent. */
private val GO_XKMS_METHODS = listOf(
    "PasswordAdd", "PasswordGet", "PasswordList", "PasswordUpdate", "PasswordDelete",
    "PasswordStoreUnlock", "PasswordStoreLock", "PasswordStoreStatus", "PasswordGenerate",
    "SealStorePut", "SealStoreGet", "SealStoreDelete", "SealStoreList", "SealStoreReseal", "SealStoreStatus"
)

/** A nil-params call as go-xkms sends it (no `params` key), and the two forms the phone must read the same. */
private val NIL_PARAMS: List<String?> = listOf(null, "null", "{}")

/**
 * `PasswordAddRequest` with every descriptive field set, in struct order. The
 * policy fields (`expires_at`, `tenant_id`, `shared`) are unset, so
 * `json.Marshal` omits them and the entry is a personal one in the default tenant.
 */
private const val FULL_ADD =
    """{"name":"GitHub","title":"Work","username":"octo","password":"hunter2","url":"https://github.com","notes":"recovery codes in the safe","folder_path":"dev"}"""

/** Each policy field, and every method whose request carries it. */
private val POLICY_METHODS = mapOf(
    "expires_at" to listOf("PasswordAdd", "PasswordUpdate"),
    "shared" to listOf("PasswordAdd"),
    "tenant_id" to listOf("PasswordAdd", "PasswordGet", "PasswordList", "PasswordUpdate", "PasswordDelete"),
    "scope" to listOf("PasswordList")
)

/** `PasswordStoreUnlockRequest` for the passphrase factor. */
private const val UNLOCK = """{"factor":"passphrase","passphrase":"correct horse"}"""

/** A Go field type, as `encoding/json` decodes into it. */
private enum class GoKind {
    STRING,
    INT,
    BOOL,

    /** `[]byte`: standard base64 with padding. */
    BYTES,

    /** `[]string`. */
    STRINGS,

    /** A slice of structs, each described by [GoField.element]. */
    STRUCTS
}

/**
 * One field of a go-xkms struct: its [kind], whether its tag lacks
 * `omitempty` so that go-xkms always reads it ([required]), and for
 * [GoKind.STRUCTS] the element struct's fields.
 */
private class GoField(val kind: GoKind, val required: Boolean, val element: Map<String, GoField>? = null)

private fun required(kind: GoKind, element: Map<String, GoField>? = null) = GoField(kind, true, element)

private fun optional(kind: GoKind) = GoField(kind, false)

private val RPC_ERROR = mapOf(
    "code" to required(GoKind.INT),
    "message" to required(GoKind.STRING)
)

/** `PageResponse`, embedded in the list responses: its fields sit in the same object. */
private val PAGE_RESPONSE = mapOf(
    "page" to required(GoKind.INT),
    "page_size" to required(GoKind.INT),
    "total" to required(GoKind.INT),
    "has_more" to required(GoKind.BOOL)
)

private val PASSWORD_ADD_RESPONSE = mapOf(
    "id" to required(GoKind.STRING),
    "name" to required(GoKind.STRING),
    "created_at" to required(GoKind.STRING)
)

private val PASSWORD_GET_RESPONSE = mapOf(
    "id" to required(GoKind.STRING),
    "name" to required(GoKind.STRING),
    "title" to optional(GoKind.STRING),
    "username" to optional(GoKind.STRING),
    "password" to optional(GoKind.STRING),
    "url" to optional(GoKind.STRING),
    "notes" to optional(GoKind.STRING),
    "folder_path" to optional(GoKind.STRING),
    "backend_id" to optional(GoKind.STRING),
    "expires_at" to optional(GoKind.STRING),
    "created_at" to required(GoKind.STRING),
    "updated_at" to required(GoKind.STRING),
    "read_only" to optional(GoKind.BOOL),
    "encrypted" to required(GoKind.BOOL),
    "owner_id" to optional(GoKind.STRING),
    "shared" to optional(GoKind.BOOL)
)

private val PASSWORD_LIST_RESPONSE =
    mapOf("passwords" to required(GoKind.STRUCTS, PASSWORD_GET_RESPONSE)) + PAGE_RESPONSE

private val PASSWORD_STORE_STATUS_RESPONSE = mapOf(
    "access_mode" to required(GoKind.STRING),
    "is_locked" to required(GoKind.BOOL),
    "barrier_sealed" to required(GoKind.BOOL),
    "auto_unsealed" to required(GoKind.BOOL),
    "password_count" to required(GoKind.INT)
)

private val PASSWORD_GENERATE_RESPONSE = mapOf("password" to required(GoKind.STRING))

private val SEAL_STORE_GET_RESPONSE = mapOf(
    "name" to required(GoKind.STRING),
    "secret" to required(GoKind.BYTES)
)

private val SEAL_STORE_LIST_RESPONSE = mapOf("names" to required(GoKind.STRINGS)) + PAGE_RESPONSE

private val SEAL_STORE_STATUS_RESPONSE = mapOf(
    "available" to required(GoKind.BOOL),
    "sealer_id" to optional(GoKind.STRING),
    "secret_count" to required(GoKind.INT),
    "secret_names" to optional(GoKind.STRINGS)
)

// -----------------------------------------------------------------------------
// Go's decoder, strictly
// -----------------------------------------------------------------------------

/** A JSON number Go decodes into an `int`: integral, which org.json parses as Int or Long. */
private fun Any.isGoInt(): Boolean = this is Int || this is Long

/**
 * Fails unless Go's `encoding/json` decodes [json] into [struct], described
 * by [fields], as go-xkms expects: each field present has its Go type and is
 * not JSON null, and each field without `omitempty` is present. Keys with no
 * field in [fields] are skipped, as Go skips them.
 */
private fun assertDecodes(struct: String, fields: Map<String, GoField>, json: JSONObject) {
    for ((name, field) in fields) {
        val path = "$struct.$name"
        if (!json.has(name)) {
            assertFalse("$path has no omitempty and must be present in $json", field.required)
            continue
        }
        assertFalse("$path must not be JSON null", json.isNull(name))
        val value: Any = json.get(name)
        when (field.kind) {
            GoKind.STRING -> assertTrue("$path must be a string: $value", value is String)
            GoKind.INT -> assertTrue("$path must be an integer: $value", value.isGoInt())
            GoKind.BOOL -> assertTrue("$path must be a bool: $value", value is Boolean)
            GoKind.BYTES -> assertBase64(path, value)
            GoKind.STRINGS -> assertArray(path, value) { i, item ->
                assertTrue("$path[$i] must be a string: $item", item is String)
            }
            GoKind.STRUCTS -> assertArray(path, value) { i, item ->
                assertTrue("$path[$i] must be an object: $item", item is JSONObject)
                assertDecodes("$path[$i]", field.element!!, item as JSONObject)
            }
        }
    }
}

private fun assertArray(path: String, value: Any, each: (Int, Any) -> Unit) {
    assertTrue("$path must be an array: $value", value is JSONArray)
    val array = value as JSONArray
    for (i in 0 until array.length()) each(i, array.get(i))
}

/** A Go `[]byte`: the standard, padded base64 `encoding/json` writes and reads. */
private fun assertBase64(path: String, value: Any) {
    assertTrue("$path must be a base64 string: $value", value is String)
    val text = value as String
    val decoded = runCatching { Base64.getDecoder().decode(text) }.getOrNull()
    assertNotNull("$path must be base64: $text", decoded)
    assertEquals("$path must be standard padded base64", Base64.getEncoder().encodeToString(decoded!!), text)
}
