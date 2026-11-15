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
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } returns prefs
        every { keystore.softwareKeys() } answers { software!! }
        every { keystore.getPublicKeyPEM(any(), any()) } returns "CREDENTIAL PUBLIC KEY"
        // A credential shares the software key's id.
        entries += "xkey_credential_$ID"
    }

    @After
    fun tearDown() {
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
        shape == Shape.ANOTHER_ID && placement == Placement.LEGACY -> KeyPresence.ABSENT
        else -> KeyPresence.UNREADABLE
    }

    private fun storeWith(shape: Shape, placement: Placement): SoftwareKeyStore {
        val filesDir = tmp.newFolder()
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        val stem = if (placement == Placement.DIGEST) digest(ID) else "legacy_$ID"
        File(dir, "$stem.key").writeBytes(ByteArray(32) { 7 })
        shape.meta?.let { File(dir, "$stem.meta").writeText(it) }
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
            val shared = runCatching { store.readShareable(ID, keystore) { software!!.get(it) } }
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
