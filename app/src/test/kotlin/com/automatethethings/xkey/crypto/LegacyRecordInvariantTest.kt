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
package com.automatethethings.xkey.crypto

import android.content.Context
import android.content.SharedPreferences
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.storage.readShareable
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate

/**
 * #255 verify r4, the fail-closed invariant over every metadata shape a
 * software key record can carry beside its material: only metadata that
 * names the id it is read for vouches for that id's key. A record whose
 * metadata is missing, empty, names no id, names an empty or non-string id,
 * cannot be parsed, or (under the id's own name) names another id, cannot
 * be attributed, so the store is [KeyPresence.UNREADABLE] for the id, never
 * absent; the key's export kind, its share read and the shared-key import's
 * read all refuse, and a credential of the same id is never exported under
 * the software key's grants.
 *
 * Each shape is tried under the id's own (digest) file name and under an
 * older build's (legacy) file name. A well-formed legacy record that names
 * another id is that id's record: the migration moves it there, so it is
 * absent for this id.
 */
class LegacyRecordInvariantTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val entries = HashSet<String>()
    private lateinit var keystore: KeystoreManager
    private var software: SoftwareKeyStore? = null

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { platform.getCertificate(any()) } answers {
            if (firstArg<String>() in entries) mockk<Certificate>(relaxed = true) else null
        }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } returns false
        every { prefs.getString(any(), any()) } answers { secondArg() }
        // Main's ML-DSA store reads the context's files directory: an empty one here.
        val keystoreContext = mockk<Context>(relaxed = true)
        every { keystoreContext.applicationContext } returns keystoreContext
        every { keystoreContext.filesDir } returns java.nio.file.Files.createTempDirectory("pqc-keys").toFile().apply { deleteOnExit() }
        keystore = spyk(KeystoreManager(keystoreContext))
        every { keystore.ed25519Prefs() } returns prefs
        every { keystore.softwareKeys() } answers { software!! }
        every { keystore.getPublicKeyPEM(any(), any()) } returns "CREDENTIAL PUBLIC KEY"
        // A credential shares the software key's id.
        entries += "xkey_credential_$ID"
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    /** A record's metadata beside its present material, or null for no metadata file. */
    private enum class Shape(val meta: String?) {
        MISSING_FILE(null),
        EMPTY_OBJECT("{}"),
        MISSING_KEY_ID("""{"algorithm":"AES","keyType":"symmetric"}"""),
        EMPTY_KEY_ID("""{"keyId":""}"""),
        ANOTHER_ID("""{"keyId":"$OTHER"}"""),
        NON_STRING_KEY_ID("""{"keyId":5}"""),
        TRUNCATED_JSON("""{"keyId":"$ID""""),
        VALID("""{"keyId":"$ID","algorithm":"AES","keyType":"symmetric","keySize":256,"exportable":true,"shareable":true}""")
    }

    private enum class Placement { DIGEST, LEGACY }

    /** What the store holds for [ID] with [shape] stored at [placement]. */
    private fun expected(shape: Shape, placement: Placement): KeyPresence = when {
        shape == Shape.VALID -> KeyPresence.PRESENT
        shape == Shape.MISSING_FILE && placement == Placement.DIGEST -> KeyPresence.PRESENT
        shape == Shape.ANOTHER_ID && placement == Placement.LEGACY -> KeyPresence.ABSENT
        else -> KeyPresence.UNREADABLE
    }

    private fun storeWith(shape: Shape, placement: Placement): SoftwareKeyStore {
        val filesDir = tmp.newFolder()
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        val stem = if (placement == Placement.DIGEST) digest(ID) else "legacy_$ID"
        File(dir, "$stem.key").writeBytes(ByteArray(32) { 7 })
        shape.meta?.let { File(dir, "$stem.meta").writeText(it) }
        return storeIn(filesDir)
    }

    private fun storeIn(filesDir: File): SoftwareKeyStore {
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        return SoftwareKeyStore(context, cipher)
    }

    @Test
    fun everyMetadataShapeBesideMaterialIsPresentOnlyWhenItNamesTheId() = runTest {
        for (placement in Placement.entries) for (shape in Shape.entries) {
            val case = "$shape at $placement"
            software = storeWith(shape, placement)
            val want = expected(shape, placement)
            assertEquals("$case presence", want, software!!.presence(ID))

            val tables = FakeKeyPolicyTables()
            val store = tables.store(KeyPolicyStore.KeyResolver { id, kind -> keystore.resolveKey(id, kind) })
            tables.addKey(ID, SharingPolicyType.ALL_PEERS)
            val kind = runCatching { keystore.exportKind(ID) }
            val shared = runCatching { store.readShareable(io.mockk.mockk<android.content.Context>(), ID, keystore, null) { software!!.get(it) } }
            if (shape == Shape.MISSING_FILE && placement == Placement.DIGEST) {
                // Material alone under the id's own digest name is that id's
                // (only its put or delete leaves it): the id holds a general
                // key, so no credential stands in, but nothing reads it.
                assertEquals("$case export kind", UserKeyKind.GENERAL, kind.getOrThrow())
                assertRefused("$case share read (local.importSharedKey)", shared.exceptionOrNull())
                assertRefused("$case software key read", runCatching { software!!.get(ID) }.exceptionOrNull())
                continue
            }
            when (want) {
                KeyPresence.UNREADABLE -> {
                    assertRefused("$case exportKind", kind.exceptionOrNull())
                    assertRefused("$case share read (local.importSharedKey)", shared.exceptionOrNull())
                    assertRefused("$case software key read", runCatching { software!!.get(ID) }.exceptionOrNull())
                }
                KeyPresence.PRESENT -> {
                    assertEquals("$case export kind", UserKeyKind.GENERAL, kind.getOrThrow())
                    val key = shared.getOrThrow()
                    assertEquals("$case shares the software key", ID, key.software?.keyId)
                    assertNull("$case shared the credential's public key", key.publicKeyPem)
                }
                KeyPresence.ABSENT -> {
                    // No software key holds the id: the credential is the id's key.
                    assertEquals("$case export kind", UserKeyKind.CREDENTIAL, kind.getOrThrow())
                    assertNull("$case read a software key", shared.getOrThrow().software)
                }
            }
        }
    }

    /**
     * #255 verify r5: an older build's record whose id is itself 64
     * lowercase hex kept that id as its file name, which looks like a
     * digest name. A record is told migrated or not by the id its metadata
     * names (its file name is the digest of that id), never by the name's
     * shape: the record is migrated, present and readable, and a credential
     * of its id is never exported in its place.
     */
    @Test
    fun aLegacyRecordNamedLikeADigestIsMigratedAndRead() = runTest {
        val hexId = "ab".repeat(32)
        entries += "xkey_credential_$hexId"
        val filesDir = tmp.newFolder()
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        File(dir, "$hexId.key").writeBytes(ByteArray(32) { 7 })
        File(dir, "$hexId.meta").writeText("""{"keyId":"$hexId","algorithm":"AES","keyType":"symmetric","keySize":256,"exportable":true,"shareable":true}""")
        software = storeIn(filesDir)

        assertEquals(KeyPresence.PRESENT, software!!.presence(hexId))
        assertEquals(hexId, software!!.get(hexId)?.keyId)
        assertEquals(UserKeyKind.GENERAL, keystore.exportKind(hexId))
        val tables = FakeKeyPolicyTables()
        val store = tables.store(KeyPolicyStore.KeyResolver { id, kind -> keystore.resolveKey(id, kind) })
        tables.addKey(hexId, SharingPolicyType.ALL_PEERS)
        val shared = store.readShareable(io.mockk.mockk<android.content.Context>(), hexId, keystore, null) { software!!.get(it) }
        assertEquals("the legacy key is shared", hexId, shared.software?.keyId)
        assertNull("the same-id credential was shared under the key's grants", shared.publicKeyPem)
        assertTrue("the record moved to its digest name", File(dir, "${digest(hexId)}.key").isFile)
    }

    /**
     * The bypass guard of the store's one record-id read: no code but
     * [SoftwareKeyStore]'s recordId reads a record's id, and nothing outside
     * the store reads its files.
     */
    @Test
    fun aRecordsIdIsReadOnlyThroughTheStoresOneRead() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val source = File(root, "com/automatethethings/xkey/crypto/SoftwareKeyStore.kt").readText()
        assertEquals("reads of a record's id", 1, Regex("""\.opt\w*\("keyId"""").findAll(source).count())
        // A name's shape never skips a record; it only keeps a record whose
        // metadata contradicts its hex name from moving or from being read
        // as the id it names, through the one identity check.
        assertTrue("the store skips records by file-name shape", "DIGEST_NAME" !in source)
        assertEquals("the digest-name shape is declared and read once", 2, Regex("""\bHEX_64\b""").findAll(source).count())
        assertTrue(
            "the digest-name shape is read outside the one identity check",
            "namesRecordOf(stem: String, id: String): Boolean =\n        stem == fileId(id) || stem == id || !HEX_64.matches(stem)" in source
        )
        assertTrue("the migration skips the one identity check", "stem != fileId(id) && namesRecordOf(stem, id)" in source)
        assertTrue("the legacy index skips the one identity check", "if (namesRecordOf(stem, id)) named.getOrPut(id)" in source)
        val outside = root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") && it.name != "SoftwareKeyStore.kt" }
            .filter { "\"software_keys\"" in it.readText() }.map { it.name }.toList()
        assertEquals("files outside the store read its records", emptyList<String>(), outside)
    }

    private fun assertRefused(what: String, failure: Throwable?) {
        assertTrue("$what did not refuse: $failure", failure is KeyPresenceUnreadableException)
    }

    private fun digest(id: String): String =
        MessageDigest.getInstance("SHA-256").digest(id.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private companion object {
        const val ID = "shared-id"
        const val OTHER = "another-id"
    }
}
