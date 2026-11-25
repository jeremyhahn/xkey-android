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
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.keyMaterialDeleter
import com.automatethethings.xkey.storage.keyMaterialGeneration
import com.automatethethings.xkey.ui.UserKeyDelete
import com.automatethethings.xkey.ui.deleteUserKey
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.KeyStore

/**
 * #255 review round 2: an Ed25519 preference store can pass contains() while
 * the read of the encrypted value fails (corrupt ciphertext), with a
 * SecurityException or a GeneralSecurityException. The generation lookup of
 * a delete read the value unguarded, so the failure escaped the screens'
 * refusal and crashed the app. Every Ed25519 value read now goes through one
 * normalizing helper and fails as [KeyPresenceUnreadableException].
 */
class Ed25519ValueReadFailureTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var filesDir: File
    private lateinit var keystore: KeystoreManager

    /** What a read of a stored value throws. */
    private var failure: Exception = SecurityException("Could not decrypt value")

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } answers { firstArg<String>() == ALIAS }
        every { prefs.getString(any(), any()) } answers {
            if (firstArg<String>() == ALIAS) throw failure else secondArg()
        }
        filesDir = tmp.newFolder()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } returns prefs
        every { keystore.softwareKeys() } returns SoftwareKeyStore(context, cipher)
        every { keystore.holdsEd25519Keys() } returns true
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    @Test
    fun aValueReadSecurityExceptionIsUnreadable() {
        assertThrowsUnreadable { keystore.userKeyGeneration(ID) }
        assertThrowsUnreadable { keyMaterialGeneration(mockk(relaxed = true), ID, keystore) }
        assertThrowsUnreadable { keystore.getEd25519PrivateKey(ALIAS) }
        assertThrowsUnreadable { keystore.deleteUserKeyGeneration(ID, mapOf("ed25519:$ALIAS" to "tag")) }
    }

    @Test
    fun aValueReadGeneralSecurityExceptionIsUnreadable() {
        failure = java.security.GeneralSecurityException("bad tag")
        assertThrowsUnreadable { keystore.userKeyGeneration(ID) }
        assertThrowsUnreadable { keyMaterialGeneration(mockk(relaxed = true), ID, keystore) }
    }

    /** The screens' delete is refused with nothing recorded, never a crash. */
    @Test
    fun aDeleteFromAKeyScreenIsRefusedNotACrash() = runTest {
        val dao = mockk<KeyPolicyDao>(relaxed = true) {
            coEvery { deletion(any()) } returns null
            coEvery { keyInstance(any()) } returns 1L
        }
        val policies = KeyPolicyStore(dao, object : KeyPolicyStore.Transactor {
            override suspend fun <T> run(block: suspend () -> T): T = block()
        })
        val key = mockk<KeyEntity> {
            every { keyId } returns ID
            every { id } returns 1L
            every { isSystemKey } returns false
        }
        val context = mockk<Context>(relaxed = true) { every { filesDir } returns this@Ed25519ValueReadFailureTest.filesDir }
        for (kind in UserKeyKind.values()) {
            val outcome = deleteUserKey(key, policies, keyMaterialDeleter(context, keystore, kind))
            assertTrue("the $kind delete was not refused: $outcome", outcome is UserKeyDelete.Refused)
        }
        coVerify(exactly = 0) { dao.putDeletion(any<KeyDeletionEntity>()) }
    }

    /** No Ed25519 preference read in KeystoreManager bypasses the normalizing helper. */
    @Test
    fun everyEd25519PreferenceReadGoesThroughTheHelper() {
        val main = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val lines = File(main, "com/automatethethings/xkey/crypto/KeystoreManager.kt").readLines()
        val read = Regex("""[pP]refs(\(\))?\??\.(getString|getAll|contains)\(""")
        val reads = lines.withIndex().filter { (_, line) -> !line.trimStart().startsWith("*") && read.containsMatchIn(line) }
        assertTrue("no Ed25519 preference read found", reads.isNotEmpty())
        val bypasses = reads.filter { (_, line) -> "ed25519Read(" !in line }
        assertTrue("Ed25519 reads outside ed25519Read: ${bypasses.map { it.index + 1 }}", bypasses.isEmpty())
    }

    private inline fun assertThrowsUnreadable(read: () -> Any?) {
        try {
            read()
        } catch (e: KeyPresenceUnreadableException) {
            return
        }
        fail("a failed value read was not reported as unreadable")
    }

    private companion object {
        const val ID = "k"
        const val ALIAS = "xkey_key_k"
    }
}
