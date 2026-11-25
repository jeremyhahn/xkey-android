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
package com.automatethethings.xkey.piv

import android.content.Context
import android.os.Build
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.SecureRandom

/**
 * Ed25519 and X25519 PIV slot keys in the device's real Android Keystore,
 * over an in-memory `piv_slots` database. Signatures and agreements are
 * checked with Bouncy Castle, not with the Keystore that made them.
 *
 * The positive cases need Android 13 and a TEE with curve 25519; on a device
 * without them they are skipped, and the refusal is checked instead. Slot 95
 * (retired 20) is used so no slot a user may hold is touched.
 */
@RunWith(AndroidJUnit4::class)
class PivCurve25519KeystoreTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: PivSlotDao
    private lateinit var manager: PivKeyManager
    private val slot = PivSlot.RETIRED_20

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.pivSlotDao()
        manager = PivKeyManager(dao)
    }

    @After
    fun tearDown() {
        runBlocking { runCatching { manager.deleteKey(slot) } }
        database.close()
    }

    @Test
    fun ed25519SlotKeySignsTheRawMessageVerifiedByBouncyCastle() = runBlocking {
        val info = generateOrSkip(PivAlgorithm.ED25519)
        val raw = PivPublicKeyEncoding.pivPublicKeyValue(info.publicKeyDer!!)
        val message = "xKey PIV Ed25519 on the device".toByteArray()

        val signature = manager.sign(slot, message)

        assertEquals(64, signature.size)
        val verifier = Ed25519Signer().apply {
            init(false, Ed25519PublicKeyParameters(raw, 0))
            update(message, 0, message.size)
        }
        assertTrue("Bouncy Castle rejects the Keystore's Ed25519 signature", verifier.verifySignature(signature))
        assertEquals(PivAlgorithm.ED25519.name, dao.getBySlotId(slot.hexId)?.algorithm)
    }

    @Test
    fun x25519SlotKeyAgreesWithBouncyCastle() = runBlocking {
        val info = generateOrSkip(PivAlgorithm.X25519)
        val phoneRaw = PivPublicKeyEncoding.pivPublicKeyValue(info.publicKeyDer!!)
        val peer = X25519KeyPairGenerator().run {
            init(X25519KeyGenerationParameters(SecureRandom()))
            generateKeyPair()
        }
        val peerRaw = (peer.public as X25519PublicKeyParameters).encoded

        val secret = manager.agree(slot, peerRaw)

        val expected = ByteArray(32)
        X25519Agreement().run {
            init(peer.private as X25519PrivateKeyParameters)
            calculateAgreement(X25519PublicKeyParameters(phoneRaw, 0), expected, 0)
        }
        assertArrayEquals(expected, secret)
    }

    @Test
    fun x25519SlotKeyCannotSignAndHasNoCertificate() = runBlocking {
        generateOrSkip(PivAlgorithm.X25519)

        val error = runCatching { manager.sign(slot, byteArrayOf(1, 2, 3)) }.exceptionOrNull()

        assertTrue("got $error", error is IllegalArgumentException)
        assertEquals("X25519 keys cannot sign", error?.message)
        assertNull(manager.getCertificate(slot))
    }

    @Test
    fun belowAndroid13Curve25519IsRefusedAndTheSlotKeepsItsKey() = runBlocking {
        val existing = manager.generateKey(slot, PivAlgorithm.ES256)
        val olderPlatform = PivKeyManager(dao, sdkInt = Build.VERSION_CODES.S_V2)

        listOf(PivAlgorithm.ED25519, PivAlgorithm.X25519).forEach { algorithm ->
            val error = runCatching { olderPlatform.generateKey(slot, algorithm) }.exceptionOrNull()
            assertTrue("$algorithm: got $error", error is PivAlgorithmUnavailableException)
            assertTrue(error?.message, error?.message?.contains("Android 13 secure hardware") == true)
        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertArrayEquals(existing.publicKeyDer, keyStore.getCertificate(slot.keystoreAlias)?.publicKey?.encoded)
        assertEquals(PivAlgorithm.ES256.name, dao.getBySlotId(slot.hexId)?.algorithm)
    }

    @Test
    fun onAnOlderDeviceTheRealManagerRefusesCurve25519() = runBlocking {
        assumeTrue("device runs Android 13 or later", Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)

        val error = runCatching { manager.generateKey(slot, PivAlgorithm.ED25519) }.exceptionOrNull()

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertNull(dao.getBySlotId(slot.hexId))
    }

    /**
     * Generates [algorithm] in the slot, skipping the test on a device that
     * cannot make it in secure hardware: the refusal itself is checked by
     * [belowAndroid13Curve25519IsRefusedAndTheSlotKeepsItsKey].
     */
    private suspend fun generateOrSkip(algorithm: PivAlgorithm): PivSlotInfo {
        assumeTrue("curve 25519 needs Android 13", Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        val result = runCatching { manager.generateKey(slot, algorithm) }
        val error = result.exceptionOrNull()
        assumeTrue("device has no secure-hardware $algorithm: $error", error !is PivAlgorithmUnavailableException)
        return result.getOrThrow()
    }
}
