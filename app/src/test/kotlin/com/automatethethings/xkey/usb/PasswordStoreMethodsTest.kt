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
import com.automatethethings.xkey.password.PasswordEntryLimit
import com.automatethethings.xkey.password.PasswordEntryTooLargeException
import com.automatethethings.xkey.password.PasswordPatch
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordVault
import com.automatethethings.xkey.password.PasswordVaultFactorRecord
import com.automatethethings.xkey.password.PasswordVaultFactorStore
import com.automatethethings.xkey.password.PasswordVaultFactorsUnreadableException
import com.automatethethings.xkey.password.SessionPasswordVault
import com.automatethethings.xkey.password.VaultUnlockAttemptStore
import com.automatethethings.xkey.password.VaultUnlockLimits
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import com.automatethethings.xkey.sync.PasswordSync
import com.automatethethings.xkey.sync.SyncEngine
import com.automatethethings.xkey.transport.StreamMessageFraming
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.MessageDigest

/**
 * Unit tests for [PasswordStoreMethods]: each of the nine password-store
 * methods with go-xkms' exact JSON names, its response shape, and an error path.
 *
 * The Keystore is stubbed with the reversible marker transform
 * [com.automatethethings.xkey.password.PasswordRepositoryTest] uses, the DAO
 * is an in-memory map, and the vault hashes with SHA-256 because Argon2 is
 * native and absent on the JVM.
 */
class PasswordStoreMethodsTest {

    private val marker: Byte = 0x7f
    private val createdAt = 1_700_000_000_000L
    private val createdAtIso = "2023-11-14T22:13:20Z"

    private lateinit var dao: InMemoryPasswordDao
    private lateinit var cipher: KeystoreAeadCipher
    private lateinit var factors: InMemoryFactorStore
    private lateinit var vault: PasswordVault
    private lateinit var repository: PasswordRepository
    private lateinit var methods: PasswordStoreMethods
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
        /** As Room's `@Update`: by row id, and never an insert. */
        override suspend fun update(password: PasswordEntity): Int {
            if (rows[password.passwordId]?.id != password.id) return 0
            rows[password.passwordId] = password
            return 1
        }
        /** As the guarded UPDATE: by row id while every column is the one read, never an insert. */
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

        /** Runs after each read by id with that id: a writer racing the reader. */
        var afterRead: (passwordId: String) -> Unit = {}
        override suspend fun getByPasswordId(passwordId: String): PasswordEntity? =
            rows[passwordId].also { afterRead(passwordId) }
        override suspend fun getByPasswordIdInTenant(passwordId: String, tenantId: String): PasswordEntity? =
            rows[passwordId]?.takeIf { it.tenantId == tenantId }.also { afterRead(passwordId) }
        /** As the listing query: tenant, sharing and folder in the WHERE clause, then ORDER BY. */
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

        /** Fails every read as `FilePasswordVaultFactorStore` does when factors.json cannot be read. */
        var unreadable = false

        override suspend fun list(): List<PasswordVaultFactorRecord> {
            if (unreadable) throw PasswordVaultFactorsUnreadableException(IOException("factors.json is a directory"))
            return records.toList()
        }
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
        cipher = mockk()
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
        dao = InMemoryPasswordDao()
        factors = InMemoryFactorStore()
        vault = PasswordVault(factors, InMemoryAttemptStore(), PassphraseHasher { passphrase, salt ->
            MessageDigest.getInstance("SHA-256").run {
                update(salt)
                digest(passphrase.toByteArray(Charsets.UTF_8))
            }
        })
        repository = PasswordRepository(dao, cipher)
        methods = PasswordStoreMethods(repository, vault, clock = { createdAt })
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private suspend fun call(method: String, params: String? = null): Response =
        methods.handle(Request(nextId++, method, params?.let { JSONObject(it) }))

    private fun Response.ok(): JSONObject {
        assertNull("unexpected error: ${error?.message}", error)
        return result!!
    }

    private fun Response.code(): Int = error!!.code

    private suspend fun addEntry(
        name: String = "GitHub",
        password: String = "hunter2",
        folder: String? = null
    ): String {
        val folderField = if (folder != null) ""","folder_path":"$folder"""" else ""
        return call(
            "PasswordAdd",
            """{"name":"$name","username":"octo","password":"$password"$folderField}"""
        ).ok().getString("id")
    }

    /** Frames a ciphertext of [response]'s length, the Noise tag included: it fails where the session would. */
    private fun writeFramed(response: Response) {
        val ciphertext = ByteArray(response.toJson().size + FrameBudget.NOISE_TAG_SIZE)
        StreamMessageFraming.writeMessage(ByteArrayOutputStream(), ciphertext)
    }

    private fun Response.resultSize(): Int = FrameBudget.serializedSize(ok())

    private fun addParams(notes: String, password: String = "hunter2"): String = JSONObject()
        .put("name", "big").put("username", "octo").put("password", password).put("notes", notes).toString()

    /**
     * Notes that make the `big` entry of [addParams] serialize, as a
     * `PasswordGetResponse`, to exactly [target] bytes. About half of them are
     * control characters, which JSON writes as six-byte escapes, so a raw
     * length would undercount them.
     */
    private suspend fun notesForEntrySize(target: Int): String {
        val probe = call("PasswordAdd", addParams("x")).ok().getString("id")
        val probeSize = call("PasswordGet", """{"id":"$probe"}""").resultSize()
        call("PasswordDelete", """{"id":"$probe"}""").ok()
        // "x" serializes to 3 bytes; e escapes then r letters to 2 + 6e + r.
        val extra = target - probeSize + 1
        val escapes = extra / 12
        return Char(1).toString().repeat(escapes) + "x".repeat(extra - 6 * escapes)
    }

    /** [count] entries with 1 KiB notes, together far larger than one frame. Returns their ids. */
    private suspend fun addLargeVault(count: Int = 100): Set<String> = (0 until count).map { i ->
        val params = JSONObject()
            .put("name", "entry-%03d".format(i)).put("password", "pw").put("notes", "n".repeat(1024))
        call("PasswordAdd", params.toString()).ok().getString("id")
    }.toSet()

    /** The page_size a refused `PasswordList` page names as fitting. */
    private fun suggestedPageSize(refused: Response): Int {
        val match = Regex("""page_size of at most (\d+)""").find(refused.error!!.message)
        return match!!.groupValues[1].toInt()
    }

    // -------------------------------------------------------------------------
    // Routing
    // -------------------------------------------------------------------------

    @Test
    fun `the family claims exactly the nine password-store methods`() {
        for (m in listOf(
            "PasswordAdd", "PasswordGet", "PasswordList", "PasswordUpdate", "PasswordDelete",
            "PasswordStoreUnlock", "PasswordStoreLock", "PasswordStoreStatus", "PasswordGenerate"
        )) {
            assertTrue(m, methods.handles(m))
        }
        assertFalse(methods.handles("PasswordStoreSetAccessMode"))
        assertFalse(methods.handles("SealStoreGet"))
    }

    @Test
    fun `the routing context names this session's vault for the shared handler's sync`() {
        assertSame(vault, methods.routingContext()[SessionPasswordVault]?.vault)
    }

    // -------------------------------------------------------------------------
    // PasswordAdd
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordAdd stores every named field and answers id, name and created_at`() = runTest {
        val result = call(
            "PasswordAdd",
            """{"name":"GitHub","title":"GitHub login","username":"octo","password":"hunter2",
               "url":"https://github.com","notes":"2fa on","folder_path":"/work"}"""
        ).ok()

        assertEquals(setOf("id", "name", "created_at"), result.keys().asSequence().toSet())
        assertEquals("GitHub", result.getString("name"))
        assertEquals(createdAtIso, result.getString("created_at"))
        val row = dao.rows.getValue(result.getString("id"))
        assertEquals("GitHub login", row.title)
        assertEquals("octo", row.username)
        assertEquals("https://github.com", row.url)
        assertEquals("2fa on", row.notes)
        assertEquals("/work", row.folderPath)
        assertFalse("the plaintext must not reach the DAO", String(row.passwordEncrypted) == "hunter2")
    }

    @Test
    fun `PasswordAdd without a password is invalid params`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordAdd", """{"name":"GitHub"}""").code())
    }

    @Test
    fun `PasswordAdd accepts an entry exactly at MAX_ENTRY_SIZE and refuses one byte more without a write`() = runTest {
        val notes = notesForEntrySize(PasswordStoreMethods.MAX_ENTRY_SIZE)

        val id = call("PasswordAdd", addParams(notes)).ok().getString("id")
        val entry = call("PasswordGet", """{"id":"$id"}""")
        assertEquals(PasswordStoreMethods.MAX_ENTRY_SIZE, entry.resultSize())
        writeFramed(entry)
        val ownPage = call("PasswordList", """{"page":1,"page_size":1}""")
        assertEquals(1, ownPage.ok().getJSONArray("passwords").length())
        writeFramed(ownPage)

        val over = call("PasswordAdd", addParams(notes + "x"))

        assertEquals(ErrorCodes.INVALID_PARAMS, over.code())
        assertEquals(setOf(id), dao.rows.keys)
    }

    // -------------------------------------------------------------------------
    // PasswordGet
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordGet answers the decrypted entry and omits empty fields`() = runTest {
        val id = addEntry(folder = "/work")

        val result = call("PasswordGet", """{"id":"$id"}""").ok()

        assertEquals(id, result.getString("id"))
        assertEquals("GitHub", result.getString("name"))
        assertEquals("octo", result.getString("username"))
        assertEquals("hunter2", result.getString("password"))
        assertEquals("/work", result.getString("folder_path"))
        assertEquals(createdAtIso, result.getString("created_at"))
        assertEquals(createdAtIso, result.getString("updated_at"))
        assertTrue(result.getBoolean("encrypted"))
        assertFalse(result.has("title"))
        assertFalse(result.has("url"))
        assertFalse(result.has("read_only"))
    }

    @Test
    fun `PasswordGet of an unknown id is not found`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("PasswordGet", """{"id":"nope"}""").code())
    }

    @Test
    fun `PasswordGet of an entry stored too large by another path answers an internal error that fits`() = runTest {
        val id = addEntry()
        dao.rows[id] = dao.rows.getValue(id).copy(notes = "n".repeat(StreamMessageFraming.MAX_MESSAGE_SIZE))

        val response = call("PasswordGet", """{"id":"$id"}""")

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.code())
        writeFramed(response)
    }

    // -------------------------------------------------------------------------
    // PasswordList
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordList filters by folder_path and never carries a password`() = runTest {
        addEntry(name = "a", folder = "/work")
        addEntry(name = "b", folder = "/home")
        addEntry(name = "c", folder = "/work")

        val result = call("PasswordList", """{"folder_path":"/work"}""").ok()

        val passwords = result.getJSONArray("passwords")
        assertEquals(2, passwords.length())
        assertEquals("a", passwords.getJSONObject(0).getString("name"))
        assertFalse(passwords.getJSONObject(0).has("password"))
        assertEquals(0, result.getInt("page"))
        assertEquals(2, result.getInt("page_size"))
        assertEquals(2, result.getInt("total"))
        assertFalse(result.getBoolean("has_more"))
    }

    @Test
    fun `PasswordList pages and sorts with the PageRequest names`() = runTest {
        addEntry(name = "a")
        addEntry(name = "b")
        addEntry(name = "c")

        val result = call(
            "PasswordList",
            """{"page":1,"page_size":2,"sort_field":"name","sort_order":1}"""
        ).ok()

        val passwords = result.getJSONArray("passwords")
        assertEquals(2, passwords.length())
        assertEquals("c", passwords.getJSONObject(0).getString("name"))
        assertEquals("b", passwords.getJSONObject(1).getString("name"))
        assertEquals(1, result.getInt("page"))
        assertEquals(2, result.getInt("page_size"))
        assertEquals(3, result.getInt("total"))
        assertTrue(result.getBoolean("has_more"))
    }

    @Test
    fun `PasswordList with a negative page is invalid params`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordList", """{"page":-1}""").code())
    }

    @Test
    fun `PasswordList refuses a page or page_size past Int or with a fraction`() = runTest {
        // 2147483648 would wrap to Int.MIN_VALUE, -2147483649 to Int.MAX_VALUE, 1.5 truncate to 1.
        for (key in listOf("page", "page_size")) {
            for (value in listOf("2147483648", "-2147483649", "1.5")) {
                val response = call("PasswordList", """{"$key":$value}""")
                assertEquals("$key $value", ErrorCodes.INVALID_PARAMS, response.code())
                assertEquals("$key $value", "$key must be an integer", response.error!!.message)
                assertNull("$key $value", response.result)
            }
        }
    }

    @Test
    fun `PasswordList takes Int MAX_VALUE as page and page_size exactly`() = runTest {
        addEntry(name = "a")

        val result = call("PasswordList", """{"page":2147483647,"page_size":2147483647}""").ok()

        assertEquals(Int.MAX_VALUE, result.getInt("page"))
        assertEquals(Int.MAX_VALUE, result.getInt("page_size"))
        assertEquals(1, result.getInt("total"))
        assertEquals(0, result.getJSONArray("passwords").length())
        assertFalse(result.getBoolean("has_more"))
    }

    @Test
    fun `PasswordList without params answers the prefix that fits with an exact total and has_more`() = runTest {
        val ids = addLargeVault()

        val response = call("PasswordList")
        writeFramed(response)

        val result = response.ok()
        val passwords = result.getJSONArray("passwords")
        assertTrue(passwords.length() in 1 until ids.size)
        assertEquals("entry-000", passwords.getJSONObject(0).getString("name"))
        assertEquals(0, result.getInt("page"))
        assertEquals(passwords.length(), result.getInt("page_size"))
        assertEquals(ids.size, result.getInt("total"))
        assertTrue(result.getBoolean("has_more"))
    }

    @Test
    fun `PasswordList refuses an explicit page that does not fit and names a page_size that does`() = runTest {
        val ids = addLargeVault()

        val refused = call("PasswordList", """{"page":1,"page_size":${ids.size}}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, refused.code())
        val message = refused.error!!.message
        assertTrue(message, message.startsWith("page 1 does not fit the frame"))
        val pageSize = suggestedPageSize(refused)
        val fitting = call("PasswordList", """{"page":1,"page_size":$pageSize}""")
        writeFramed(fitting)
        assertEquals(pageSize, fitting.ok().getJSONArray("passwords").length())
    }

    @Test
    fun `PasswordList pages through a vault larger than a frame and returns every entry exactly once`() = runTest {
        val ids = addLargeVault()
        val pageSize = suggestedPageSize(call("PasswordList", """{"page":1,"page_size":${ids.size}}"""))

        val seen = mutableListOf<String>()
        var page = 1
        do {
            val response = call("PasswordList", """{"page":$page,"page_size":$pageSize}""")
            writeFramed(response)
            val result = response.ok()
            assertEquals(ids.size, result.getInt("total"))
            val passwords = result.getJSONArray("passwords")
            (0 until passwords.length()).mapTo(seen) { passwords.getJSONObject(it).getString("id") }
            page++
        } while (result.getBoolean("has_more"))

        assertTrue("one page held the whole vault", page > 2)
        assertEquals(ids.size, seen.size)
        assertEquals(ids, seen.toSet())
    }

    /** Stores an entry named [name] with notes over a whole frame, as a writer before the size limit could. */
    private suspend fun addOversizedEntry(name: String): String {
        val id = addEntry(name = name)
        dao.rows[id] = dao.rows.getValue(id).copy(notes = "n".repeat(StreamMessageFraming.MAX_MESSAGE_SIZE))
        return id
    }

    @Test
    fun `PasswordList lists an oversized entry that sorts first in minimal form and every entry after it whole`() = runTest {
        val big = addOversizedEntry("aaa")
        val ordinary = listOf("b", "c", "d").map { addEntry(name = it) }

        val response = call("PasswordList")
        writeFramed(response)

        val result = response.ok()
        val passwords = result.getJSONArray("passwords")
        assertEquals(4, passwords.length())
        assertEquals(4, result.getInt("total"))
        assertFalse(result.getBoolean("has_more"))
        val minimal = passwords.getJSONObject(0)
        assertEquals(
            setOf("id", "name", "created_at", "updated_at", "encrypted"),
            minimal.keys().asSequence().toSet()
        )
        assertEquals(big, minimal.getString("id"))
        assertEquals("aaa", minimal.getString("name"))
        assertEquals(createdAtIso, minimal.getString("created_at"))
        assertEquals(createdAtIso, minimal.getString("updated_at"))
        assertTrue(minimal.getBoolean("encrypted"))
        for ((i, id) in ordinary.withIndex()) {
            val item = passwords.getJSONObject(i + 1)
            assertEquals(id, item.getString("id"))
            assertEquals("octo", item.getString("username"))
            assertFalse(item.has("password"))
        }
    }

    @Test
    fun `PasswordList pages of one list an oversized entry and every other entry exactly once`() = runTest {
        val ids = listOf(addOversizedEntry("aaa")) + listOf("b", "c", "d").map { addEntry(name = it) }

        val seen = mutableListOf<String>()
        var page = 1
        do {
            val response = call("PasswordList", """{"page":$page,"page_size":1}""")
            writeFramed(response)
            val result = response.ok()
            val passwords = result.getJSONArray("passwords")
            assertEquals(1, passwords.length())
            seen += passwords.getJSONObject(0).getString("id")
            page++
        } while (result.getBoolean("has_more"))

        assertEquals(ids, seen)
    }

    @Test
    fun `PasswordList caps only the listed copy of a name too large to list`() = runTest {
        val id = addEntry(name = "big")
        val name = "a".repeat(StreamMessageFraming.MAX_MESSAGE_SIZE)
        dao.rows[id] = dao.rows.getValue(id).copy(name = name)
        val other = addEntry(name = "b")

        val response = call("PasswordList")
        writeFramed(response)

        val passwords = response.ok().getJSONArray("passwords")
        assertEquals(2, passwords.length())
        assertEquals(name.take(PasswordEntryLimit.MINIMAL_NAME_CHARS), passwords.getJSONObject(0).getString("name"))
        assertEquals(other, passwords.getJSONObject(1).getString("id"))
        assertEquals(name, dao.rows.getValue(id).name)
        call("PasswordDelete", """{"id":"$id"}""").ok()
        assertNull(dao.rows[id])
    }

    /** Stores an entry under [id], named [id], as sync stored a nameless entry before any writer was held to the limit. */
    private suspend fun addLegacyEntryWithId(id: String): String {
        val stored = dao.rows.remove(addEntry(name = "legacy"))!!
        dao.rows[id] = stored.copy(passwordId = id, name = id)
        return id
    }

    private fun listedIds(result: JSONObject): List<String> {
        val passwords = result.getJSONArray("passwords")
        return (0 until passwords.length()).map { passwords.getJSONObject(it).getString("id") }
    }

    @Test
    fun `PasswordList lists a legacy 65,000-char id whole, with only the name that fits beside it`() = runTest {
        val longId = addLegacyEntryWithId("a".repeat(65_000))
        val others = listOf("b", "c", "d").map { addEntry(name = it) }

        val response = call("PasswordList")
        writeFramed(response)

        // The item fills MAX_ENTRY_SIZE, so RESULT_BUDGET leaves beside it only what
        // pageOverhead holds over this page's narrower numbers, too little for any
        // other entry: page 0 answers the long id alone, and the pages-of-one test
        // reaches the entries after it.
        val result = response.ok()
        assertEquals(listOf(longId), listedIds(result))
        assertEquals(others.size + 1, result.getInt("total"))
        assertTrue(result.getBoolean("has_more"))
        val item = result.getJSONArray("passwords").getJSONObject(0)
        // ASCII is one byte a char, so the longest name that fits fills the item exactly.
        assertEquals(PasswordEntryLimit.MAX_ENTRY_SIZE, FrameBudget.serializedSize(item))
        val name = item.getString("name")
        assertTrue(name.length < PasswordEntryLimit.MINIMAL_NAME_CHARS)
        assertTrue(longId.startsWith(name))
    }

    @Test
    fun `PasswordList pages of one answer a legacy 65,000-char id and every entry after it`() = runTest {
        val ids = listOf(addLegacyEntryWithId("a".repeat(65_000))) + listOf("b", "c", "d").map { addEntry(name = it) }

        val seen = mutableListOf<String>()
        var page = 1
        do {
            val response = call("PasswordList", """{"page":$page,"page_size":1}""")
            writeFramed(response)
            val result = response.ok()
            seen += listedIds(result)
            page++
        } while (result.getBoolean("has_more"))

        assertEquals(ids, seen)
    }

    @Test
    fun `PasswordList leaves out a legacy id too large to list, lists every entry after it, and logs no id`() = runTest {
        mockkStatic(Log::class)
        every { Log.w(any(), any<String>()) } returns 0
        val unlistable = addLegacyEntryWithId("a".repeat(PasswordEntryLimit.MAX_ENTRY_SIZE))
        val others = listOf("b", "c", "d").map { addEntry(name = it) }

        val all = call("PasswordList")
        writeFramed(all)
        val result = all.ok()
        assertEquals(others, listedIds(result))
        assertEquals(others.size, result.getInt("total"))
        assertFalse(result.getBoolean("has_more"))

        val page = call("PasswordList", """{"page":1,"page_size":2}""")
        writeFramed(page)
        assertEquals(others.take(2), listedIds(page.ok()))

        verify(exactly = 2) { Log.w(any(), match<String> { !it.contains(unlistable) }) }
        // The phone UI deletes it by id, as PasswordManagementActivity does.
        assertTrue(repository.delete(unlistable))
        assertNull(dao.rows[unlistable])
    }

    @Test
    fun `a list item keeps the longest listable id whole and gives up one char past it`() {
        val empty = PasswordRecord(passwordId = "", name = "", password = "", createdAt = createdAt, updatedAt = createdAt)
        // Empty, an entry's list item is exactly the minimal one: what an id is listed around.
        val around = FrameBudget.serializedSize(PasswordEntryLimit.listItem(empty)!!)
        val longest = empty.copy(passwordId = "a".repeat(PasswordEntryLimit.MAX_ENTRY_SIZE - around), name = "named")

        val item = PasswordEntryLimit.listItem(longest)!!

        assertEquals(longest.passwordId, item.getString("id"))
        assertEquals("", item.getString("name"))
        assertEquals(PasswordEntryLimit.MAX_ENTRY_SIZE, FrameBudget.serializedSize(item))
        assertNull(PasswordEntryLimit.listItem(longest.copy(passwordId = longest.passwordId + "a")))
    }

    @Test
    fun `PasswordSync merge refuses an id too large to list, as every writer does`() = runTest {
        val incoming = JSONArray()
            .put(JSONObject().put("id", "a".repeat(PasswordEntryLimit.MAX_ENTRY_SIZE)).put("password", "pw"))

        val counts = PasswordSync(repository, factors).merge(incoming)

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), counts)
        assertTrue(dao.rows.isEmpty())
    }

    // -------------------------------------------------------------------------
    // The size guard every writer shares (PasswordRepository)
    // -------------------------------------------------------------------------

    /** An entry with notes over a whole frame, too large for any writer to store. */
    private fun oversizedRecord(id: String) = PasswordRecord(
        passwordId = id,
        name = "big",
        password = "pw",
        notes = "n".repeat(StreamMessageFraming.MAX_MESSAGE_SIZE)
    )

    @Test
    fun `PasswordSync merge skips an entry too large to read back and leaves the stored row alone`() = runTest {
        repository.upsert(PasswordRecord(passwordId = "pwd-big", name = "big", password = "old"))
        val before = dao.rows.getValue("pwd-big")
        val incoming = JSONArray()
            .put(
                JSONObject().put("id", "pwd-big").put("name", "big").put("password", "pw")
                    .put("notes", "n".repeat(StreamMessageFraming.MAX_MESSAGE_SIZE))
            )
            .put(JSONObject().put("id", "pwd-small").put("name", "small").put("password", "pw"))

        val counts = PasswordSync(repository, factors).merge(incoming)

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 1), counts)
        assertSame(before, dao.rows.getValue("pwd-big"))
        assertEquals(setOf("pwd-big", "pwd-small"), dao.rows.keys)
    }

    @Test
    fun `PasswordRepository upsert, the phone UI's save, refuses an oversized entry without a write`() = runTest {
        val refused = runCatching { repository.upsert(oversizedRecord("pwd-ui")) }.exceptionOrNull()

        assertTrue("$refused", refused is PasswordEntryTooLargeException)
        assertFalse(refused!!.message!!.contains("nnnn"))
        assertTrue(dao.rows.isEmpty())
        verify(exactly = 0) { cipher.encrypt(any()) }
    }

    @Test
    fun `PasswordRepository updateFields refuses growing an entry past the limit without a write`() = runTest {
        val id = addEntry()
        val before = dao.rows.getValue(id)

        val notes = oversizedRecord(id).notes
        val keepingPassword = runCatching {
            repository.updateFields(id, PasswordPatch(notes = notes))
        }.exceptionOrNull()
        val newPassword = runCatching {
            repository.updateFields(id, PasswordPatch(password = "n3w", notes = notes))
        }.exceptionOrNull()

        assertTrue("$keepingPassword", keepingPassword is PasswordEntryTooLargeException)
        assertTrue("$newPassword", newPassword is PasswordEntryTooLargeException)
        assertSame(before, dao.rows.getValue(id))
    }

    // -------------------------------------------------------------------------
    // PasswordUpdate
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordUpdate changes present fields and leaves absent and null ones unchanged`() = runTest {
        val id = addEntry()

        val result = call(
            "PasswordUpdate",
            """{"id":"$id","password":"n3w","url":"https://example.com","username":null}"""
        ).ok()

        assertEquals(0, result.length())
        val entry = call("PasswordGet", """{"id":"$id"}""").ok()
        assertEquals("n3w", entry.getString("password"))
        assertEquals("https://example.com", entry.getString("url"))
        assertEquals("octo", entry.getString("username"))
        assertEquals("GitHub", entry.getString("name"))
    }

    @Test
    fun `PasswordUpdate without a password keeps the ciphertext and never decrypts`() = runTest {
        val id = addEntry()
        val before = dao.rows.getValue(id).passwordEncrypted

        call("PasswordUpdate", """{"id":"$id","notes":"rotated"}""").ok()

        verify(exactly = 0) { cipher.decrypt(any()) }
        assertTrue(before.contentEquals(dao.rows.getValue(id).passwordEncrypted))
        assertEquals("rotated", dao.rows.getValue(id).notes)
    }

    @Test
    fun `PasswordUpdate of an unknown id is not found`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("PasswordUpdate", """{"id":"nope","name":"x"}""").code())
    }

    @Test
    fun `PasswordUpdate of an entry deleted between the repository's read and write is not found and stays deleted`() = runTest {
        val id = addEntry()
        // The repository's read is the only one before its write: the phone UI deletes right after it.
        // The write then finds no row, and the one re-read, the second read, finds none either.
        var reads = 0
        dao.afterRead = { if (++reads == 1) dao.rows.remove(it) }

        val response = call("PasswordUpdate", """{"id":"$id","password":"rotated","notes":"rotated"}""")

        assertEquals(2, reads)
        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.code())
        assertTrue("the deleted entry must not be recreated", dao.rows.isEmpty())
    }

    @Test
    fun `PasswordUpdate keeps a field another writer changed after the read when the request leaves it unset`() = runTest {
        val id = addEntry()
        // A sync changes the notes, and only the notes, as soon as the repository has read the entry.
        var reads = 0
        dao.afterRead = {
            if (++reads == 1) dao.rows[it] = dao.rows.getValue(it).copy(notes = "sync notes", updatedAt = 1L)
        }

        call("PasswordUpdate", """{"id":"$id","url":"https://example.com"}""").ok()

        assertEquals(2, reads)
        assertEquals("the other writer's notes must not be overwritten", "sync notes", dao.rows.getValue(id).notes)
        assertEquals("https://example.com", dao.rows.getValue(id).url)
    }

    @Test
    fun `PasswordUpdate grows an entry to exactly MAX_ENTRY_SIZE and refuses one byte more without a write`() = runTest {
        val notes = notesForEntrySize(PasswordStoreMethods.MAX_ENTRY_SIZE)
        val id = call("PasswordAdd", addParams("x")).ok().getString("id")

        call("PasswordUpdate", JSONObject().put("id", id).put("notes", notes).toString()).ok()
        val entry = call("PasswordGet", """{"id":"$id"}""")
        assertEquals(PasswordStoreMethods.MAX_ENTRY_SIZE, entry.resultSize())
        writeFramed(entry)
        val before = dao.rows.getValue(id).passwordEncrypted

        val longerNotes = call("PasswordUpdate", JSONObject().put("id", id).put("notes", notes + "x").toString())
        val longerPassword = call("PasswordUpdate", JSONObject().put("id", id).put("password", "hunter2x").toString())

        assertEquals(ErrorCodes.INVALID_PARAMS, longerNotes.code())
        assertEquals(ErrorCodes.INVALID_PARAMS, longerPassword.code())
        assertEquals(notes, dao.rows.getValue(id).notes)
        assertTrue(before.contentEquals(dao.rows.getValue(id).passwordEncrypted))
    }

    // -------------------------------------------------------------------------
    // PasswordDelete
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordDelete removes the entry and answers an empty result`() = runTest {
        val id = addEntry()

        val result = call("PasswordDelete", """{"id":"$id"}""").ok()

        assertEquals(0, result.length())
        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun `PasswordDelete of an unknown id is not found`() = runTest {
        assertEquals(ErrorCodes.KEY_NOT_FOUND, call("PasswordDelete", """{"id":"nope"}""").code())
    }

    // -------------------------------------------------------------------------
    // PasswordStoreUnlock
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordStoreUnlock with the enrolled passphrase unlocks the store`() = runTest {
        vault.enrollPassphrase("correct horse")
        assertEquals(ErrorCodes.PASSWORD_STORE_LOCKED, call("PasswordList").code())

        val result = call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"correct horse"}""").ok()

        assertEquals(0, result.length())
        assertNotNull(call("PasswordList").result)
    }

    @Test
    fun `PasswordStoreUnlock with a wrong passphrase is rejected without detail`() = runTest {
        vault.enrollPassphrase("correct horse")

        val response = call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"wrong"}""")

        assertEquals(ErrorCodes.VAULT_CREDENTIAL_REJECTED, response.code())
        assertEquals("password vault credential rejected", response.error!!.message)
        assertNull(response.error!!.data)
        assertEquals(ErrorCodes.PASSWORD_STORE_LOCKED, call("PasswordList").code())
    }

    @Test
    fun `PasswordStoreUnlock past the PIN attempt limit answers PIN_LOCKED without detail`() = runTest {
        vault.enrollPassphrase("correct horse")
        repeat(PinSettingsData().maxPinAttempts) {
            call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"wrong"}""")
        }

        val response = call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"correct horse"}""")

        assertEquals(ErrorCodes.PIN_LOCKED, response.code())
        assertEquals("password vault is locked out", response.error!!.message)
        assertNull(response.error!!.data)
        assertEquals(ErrorCodes.PASSWORD_STORE_LOCKED, call("PasswordList").code())
    }

    @Test
    fun `PasswordStoreUnlock with the old user_pin body is invalid params`() = runTest {
        vault.enrollPassphrase("correct horse")

        val response = call("PasswordStoreUnlock", """{"user_pin":"123456"}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, response.code())
        assertFalse(response.error!!.message.contains("123456"))
    }

    @Test
    fun `PasswordStoreUnlock before any enrollment is not initialized`() = runTest {
        val response = call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"x"}""")

        assertEquals(ErrorCodes.VAULT_NOT_INITIALIZED, response.code())
    }

    // -------------------------------------------------------------------------
    // PasswordStoreLock
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordStoreLock relocks the store and answers an empty result`() = runTest {
        vault.enrollPassphrase("correct horse")
        call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"correct horse"}""").ok()

        val result = call("PasswordStoreLock").ok()

        assertEquals(0, result.length())
        assertEquals(ErrorCodes.PASSWORD_STORE_LOCKED, call("PasswordGet", """{"id":"x"}""").code())
    }

    @Test
    fun `PasswordStoreLock before any enrollment is not initialized`() = runTest {
        assertEquals(ErrorCodes.VAULT_NOT_INITIALIZED, call("PasswordStoreLock").code())
    }

    private suspend fun assertFactorsUnreadable(block: suspend () -> Unit) {
        try {
            block()
            throw AssertionError("expected PasswordVaultFactorsUnreadableException")
        } catch (e: PasswordVaultFactorsUnreadableException) {
            // expected
        }
    }

    @Test
    fun `PasswordStoreLock that cannot read the factors fails and still locks the store`() = runTest {
        vault.enrollPassphrase("correct horse")
        call("PasswordStoreUnlock", """{"factor":"passphrase","passphrase":"correct horse"}""").ok()
        val id = addEntry()
        factors.unreadable = true

        assertEquals(ErrorCodes.INTERNAL_ERROR, call("PasswordStoreLock").code())

        assertFalse("a failed lock must not leave the vault unlocked", vault.isUnlocked())
        assertEquals(ErrorCodes.INTERNAL_ERROR, call("PasswordGet", """{"id":"$id"}""").error?.code)
        // local.syncPasswords: the shared handler's sync under this session's routing context.
        val sync = PasswordSync(repository, factors)
        val before = dao.rows.toMap()
        withContext(methods.routingContext()) {
            assertFactorsUnreadable { sync.gather() }
            assertFactorsUnreadable {
                sync.merge(JSONArray().put(JSONObject().put("id", "remote-1").put("password", "pw")))
            }
        }
        assertEquals(before, dao.rows.toMap())
    }

    // -------------------------------------------------------------------------
    // PasswordStoreStatus
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordStoreStatus answers every PasswordStoreStatusResponse field`() = runTest {
        addEntry()
        addEntry(name = "other")

        val result = call("PasswordStoreStatus").ok()

        assertEquals("local", result.getString("access_mode"))
        assertFalse(result.getBoolean("is_locked"))
        assertFalse(result.getBoolean("barrier_sealed"))
        assertFalse(result.getBoolean("auto_unsealed"))
        assertEquals(2, result.getInt("password_count"))
    }

    @Test
    fun `PasswordStoreStatus reports a locked vault as is_locked`() = runTest {
        vault.enrollPassphrase("correct horse")

        assertTrue(call("PasswordStoreStatus").ok().getBoolean("is_locked"))
    }

    @Test
    fun `PasswordStoreStatus failing in storage is an internal error that leaks nothing`() = runTest {
        dao.failing = true

        val response = call("PasswordStoreStatus")

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.code())
        assertFalse(response.error!!.message.contains("secret-entry-content"))
    }

    // -------------------------------------------------------------------------
    // PasswordGenerate
    // -------------------------------------------------------------------------

    @Test
    fun `PasswordGenerate honours length and the selected classes`() = runTest {
        val password = call(
            "PasswordGenerate",
            """{"length":40,"upper":false,"lower":true,"digits":true,"symbols":false}"""
        ).ok().getString("password")

        assertEquals(40, password.length)
        assertTrue(password.all { it in 'a'..'z' || it in '0'..'9' })
        assertTrue(password.any { it in 'a'..'z' })
        assertTrue(password.any { it in '0'..'9' })
    }

    @Test
    fun `PasswordGenerate draws only from charset when one is given`() = runTest {
        val password = call("PasswordGenerate", """{"length":16,"charset":"ab"}""").ok().getString("password")

        assertEquals(16, password.length)
        assertTrue(password.all { it == 'a' || it == 'b' })
    }

    /** The generated password as the desktop reads it: through the response's UTF-8 JSON on the wire. */
    private suspend fun generatedOverTheWire(params: String): String {
        val wire = call("PasswordGenerate", params).toJsonString().toByteArray(Charsets.UTF_8)
        return Response.fromJson(wire).ok().getString("password")
    }

    @Test
    fun `PasswordGenerate picks a supplementary charset character whole`() = runTest {
        assertEquals("😀", generatedOverTheWire("""{"length":1,"charset":"😀"}"""))
    }

    @Test
    fun `PasswordGenerate counts length in code points, each from a mixed charset`() = runTest {
        val charset = "abé😀𝄞"
        val allowed = charset.codePoints().toArray().toSet()

        val password = generatedOverTheWire("""{"length":64,"charset":"$charset"}""")

        val codePoints = password.codePoints().toArray()
        assertEquals(64, codePoints.size)
        assertTrue(codePoints.all { it in allowed })
        // A lone surrogate is its own code point here, so none means every pair is whole.
        assertTrue(codePoints.none { it in 0xD800..0xDFFF })
    }

    @Test
    fun `PasswordGenerate refuses a charset holding an unpaired surrogate`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordGenerate", """{"length":4,"charset":"a\ud800"}""").code())
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordGenerate", """{"length":4,"charset":"\ude00\ud83d"}""").code())
    }

    @Test
    fun `PasswordGenerate over the maximum length is invalid params`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("PasswordGenerate", """{"length":257}""").code())
    }

    @Test
    fun `PasswordGenerate refuses a length past Int instead of wrapping it into the bounds`() = runTest {
        // org.json reads 4294967300 as a Long; narrowed with toInt it would be 4.
        val response = call("PasswordGenerate", """{"length":4294967300}""")

        assertEquals(ErrorCodes.INVALID_PARAMS, response.code())
        assertEquals("length must be an integer", response.error!!.message)
        assertNull(response.result)
    }

    @Test
    fun `PasswordGenerate refuses a fractional length and takes an integral one written with a fraction`() = runTest {
        val fractional = call("PasswordGenerate", """{"length":4.5}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, fractional.code())
        assertEquals("length must be an integer", fractional.error!!.message)
        assertNull(fractional.result)

        val password = call("PasswordGenerate", """{"length":16.0,"lower":true}""").ok().getString("password")
        assertEquals(16, password.length)
        assertTrue(password.all { it in 'a'..'z' })
    }

    @Test
    fun `PasswordGenerate length at the Int limits reaches the length bound exactly`() = runTest {
        // Int.MAX_VALUE parses and is refused by the 0..256 bound, not by the parser.
        val max = call("PasswordGenerate", """{"length":2147483647}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, max.code())
        assertEquals("length must be between 0 and 256", max.error!!.message)

        // One past Int.MIN_VALUE would wrap to Int.MAX_VALUE; the parser refuses it first.
        val belowMin = call("PasswordGenerate", """{"length":-2147483649}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, belowMin.code())
        assertEquals("length must be an integer", belowMin.error!!.message)
    }
}
