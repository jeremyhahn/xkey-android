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
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.SecureRandom
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The phone's Noise identity, as it is read back from encrypted storage.
 *
 * Early builds stored the X25519 static keypair in its Java encodings — PKCS#8
 * for the private half, X.509 for the public half — while the Noise protocol
 * only ever works with the raw 32 bytes. [NoiseSession] therefore carries a
 * migration: it recognises both encodings, strips the header, and rewrites the
 * store in raw form so the conversion happens exactly once.
 *
 * Nothing else exercises that path. A phone upgraded from such a build has an
 * identity that either survives the migration or silently becomes a *different*
 * identity — which does not fail loudly, it fails as "every desktop I had
 * paired now refuses to connect", because the static key is what the peer
 * pinned and what the prologue is bound to.
 *
 * The storage is `EncryptedSharedPreferences`, so this only runs on a device.
 * The real identity is snapshotted and restored around every test; a run that
 * left a synthetic key in place would break every other BLE suite on the
 * device.
 */
@RunWith(AndroidJUnit4::class)
class NoiseStaticKeyMigrationTest {

    private lateinit var context: Context
    private lateinit var prefs: SharedPreferences

    private var savedPrivate: String? = null
    private var savedPublic: String? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        prefs = openKeyStore()
        savedPrivate = prefs.getString(KEY_STATIC_PRIVATE, null)
        savedPublic = prefs.getString(KEY_STATIC_PUBLIC, null)
    }

    @After
    fun tearDown() {
        if (::prefs.isInitialized) {
            prefs.edit().apply {
                if (savedPrivate != null) putString(KEY_STATIC_PRIVATE, savedPrivate)
                else remove(KEY_STATIC_PRIVATE)
                if (savedPublic != null) putString(KEY_STATIC_PUBLIC, savedPublic)
                else remove(KEY_STATIC_PUBLIC)
            }.commit()
        }
        savedPrivate = null
        savedPublic = null
    }

    /**
     * The same identity comes back out, in raw form, and the store is rewritten
     * so the next load has nothing left to convert.
     */
    @Test
    fun aLegacyEncodedIdentityIsConvertedAndRewrittenRaw(): Unit = runBlocking {
        val rawPrivate = randomKey()
        val rawPublic = randomKey()
        store(PKCS8_X25519_HEADER + rawPrivate, X509_X25519_HEADER + rawPublic)

        val session = NoiseSession()
        session.loadStaticKey(context)

        assertArrayEquals(
            "the identity must survive the conversion unchanged",
            rawPublic,
            session.getStaticPublicKey()
        )

        val stored = NoiseSession.getStoredStaticKeyPair(context)
        assertNotNull(stored)
        assertArrayEquals(rawPrivate, stored!!.privateKey)
        assertArrayEquals(rawPublic, stored.publicKey)

        assertEquals(
            "the private half must have been rewritten without its PKCS#8 header",
            32,
            decode(KEY_STATIC_PRIVATE).size
        )
        assertEquals(
            "the public half must have been rewritten without its X.509 header",
            32,
            decode(KEY_STATIC_PUBLIC).size
        )
    }

    /** An identity already in raw form is loaded as-is and left alone. */
    @Test
    fun aRawIdentityIsLoadedUntouched(): Unit = runBlocking {
        val rawPrivate = randomKey()
        val rawPublic = randomKey()
        store(rawPrivate, rawPublic)
        val before = prefs.getString(KEY_STATIC_PRIVATE, null)

        val session = NoiseSession()
        session.loadStaticKey(context)

        assertArrayEquals(rawPublic, session.getStaticPublicKey())
        assertEquals("nothing needed rewriting", before, prefs.getString(KEY_STATIC_PRIVATE, null))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun openKeyStore(): SharedPreferences = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun store(privateKey: ByteArray, publicKey: ByteArray) {
        prefs.edit()
            .putString(KEY_STATIC_PRIVATE, Base64.getEncoder().encodeToString(privateKey))
            .putString(KEY_STATIC_PUBLIC, Base64.getEncoder().encodeToString(publicKey))
            .commit()
    }

    private fun decode(key: String): ByteArray =
        Base64.getDecoder().decode(prefs.getString(key, null))

    private fun randomKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        /** Mirrors the private constants in [NoiseSession]. */
        const val PREFS_NAME = "xkey_noise_keys"
        const val KEY_STATIC_PRIVATE = "static_private_key"
        const val KEY_STATIC_PUBLIC = "static_public_key"

        /** `302e020100300506032b656e04220420`, the PKCS#8 prefix for X25519. */
        val PKCS8_X25519_HEADER = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        )

        /** `302a300506032b656e032100`, the X.509 prefix for X25519. */
        val X509_X25519_HEADER = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x6e, 0x03, 0x21, 0x00
        )
    }
}
