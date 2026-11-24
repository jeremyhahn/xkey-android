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

package com.automatethethings.xkey.crypto

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import java.util.Collections
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A software ML-DSA key through [KeystoreManager] from generation to
 * deletion: it keeps the user-authentication policy it was made with however
 * a caller asks it to sign, and once its key goes, nothing signs with it.
 */
class KeystoreManagerPqcLifecycleTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val keyStore = mockk<KeyStore>(relaxed = true)
    private lateinit var context: Context
    private lateinit var store: PqcSoftwareKeyStore
    private lateinit var manager: KeystoreManager
    private lateinit var defaultClock: () -> Long

    /** The fake clock's time, in the store's clock base. */
    private var now = 1_000_000L

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        every { keyStore.containsAlias(any()) } returns false
        every { keyStore.aliases() } answers { Collections.emptyEnumeration() }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit

        // A stand-in seal: the bytes reversed.
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        context = mockk(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        store = PqcSoftwareKeyStore(context, cipher)

        defaultClock = PqcSoftwareKeyStore.clock
        PqcSoftwareKeyStore.clock = { now }
        manager = KeystoreManager(context, sdkInt = 34, pqcStore = store)
    }

    @After
    fun tearDown() {
        PqcSoftwareKeyStore.clock = defaultClock
        unmockkAll()
    }

    private fun generate(keyId: String, authDurationSeconds: Int): ByteArray =
        manager.generateMlDsaKey(keyId, SET, PqcBacking.SOFTWARE, authDurationSeconds = authDurationSeconds)

    private fun signApproved(keyId: String, spki: ByteArray, userAuthenticatedAt: Long? = null): ByteArray =
        runBlocking {
            manager.signApprovedMlDsa(KeystoreManager.generalKeyAlias(keyId), spki, DATA, SET, userAuthenticatedAt)
        }

    @Test
    fun `a per-use software key refuses to sign without a user authentication`() {
        val spki = generate("perUse", 0)

        assertTrue(manager.pqcSoftwareKeyRequiresUserAuth("perUse"))
        assertThrows(BiometricRequiredException::class.java) { signApproved("perUse", spki) }
        assertThrows("an old authentication is not this use", BiometricRequiredException::class.java) {
            signApproved("perUse", spki, userAuthenticatedAt = now - 60_000)
        }
        assertEquals(SET.signatureBytes, signApproved("perUse", spki, userAuthenticatedAt = now).size)
    }

    @Test
    fun `a time-window software key signs only inside its window`() {
        val spki = generate("window", 30)

        assertTrue(manager.pqcSoftwareKeyRequiresUserAuth("window"))
        assertThrows(BiometricRequiredException::class.java) { signApproved("window", spki) }
        assertThrows(BiometricRequiredException::class.java) {
            signApproved("window", spki, userAuthenticatedAt = now - 31_000)
        }
        assertThrows("an authentication from the future is refused", BiometricRequiredException::class.java) {
            signApproved("window", spki, userAuthenticatedAt = now + 1_000)
        }
        assertEquals(SET.signatureBytes, signApproved("window", spki, userAuthenticatedAt = now - 10_000).size)
    }

    @Test
    fun `a software key made without user authentication signs without one`() {
        val spki = generate("open", -1)

        assertFalse(manager.pqcSoftwareKeyRequiresUserAuth("open"))
        assertEquals(SET.signatureBytes, signApproved("open", spki).size)
    }

    @Test
    fun `a caller that skips the manager and signs through the store is refused too`() {
        generate("direct", 0)
        val alias = KeystoreManager.generalKeyAlias("direct")

        assertThrows(BiometricRequiredException::class.java) { store.sign(alias, DATA) }
        assertEquals(SET.signatureBytes, store.sign(alias, DATA, userAuthenticatedAt = now).size)
    }

    private companion object {
        val SET = MlDsaParameterSet.ML_DSA_44
        val DATA = "message".toByteArray()
    }
}
