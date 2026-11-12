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
package com.automatethethings.xkey.remote

import com.automatethethings.xkey.crypto.FileEncryptor
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.deleteKeyRow
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Writers that remove key material while a desktop share of a key waits for
 * transport admission: the share sends only a key whose material still
 * stands, never the cached public half of a key already removed.
 */
class KeyMaterialRemovalShareTest {

    private lateinit var router: BidirectionalMessageRouter

    private val peer = "cd".repeat(32)
    private val pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    private val accepted = """{"accepted":true,"import_id":"shared-k","backend":"software"}"""
    private val isShared: suspend (String, String) -> Boolean = { _, _ -> false }

    /** The key rows as the store holds them now. */
    private val stored = mutableMapOf<String, KeyEntity>()
    private val current: suspend (String) -> KeyEntity? = { stored[it] }

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun session(s: ScriptedMessageSender, stillCurrent: (ShareSession) -> Boolean): ShareSession {
        s.confirmedPeer = peer
        return ShareSession.of(listOf(ShareSession.Transport(s, router)), stillCurrent)!!
    }

    private fun row(keyId: String, source: String = "local") = KeyEntity(
        keyId = keyId,
        keyType = "signing",
        algorithm = "EC",
        label = keyId,
        keySizeBits = 256,
        sharingPolicy = SharingPolicyType.ALL_PEERS,
        source = source
    ).also { stored[it.keyId] = it }

    @Test
    fun `KeyDetailActivity deleting software key xkey_key_a leaves hardware key a and its pending share`() = runTest {
        softwareRowDeletedWhileAShareOfTheHardwareKeyWaits("KeyDetailActivity.deleteKey")
    }

    @Test
    fun `KeyManagementActivity deleting software key xkey_key_a leaves hardware key a and its pending share`() = runTest {
        softwareRowDeletedWhileAShareOfTheHardwareKeyWaits("KeyManagementActivity.deleteKey")
    }

    /**
     * Software key `xkey_key_a` and hardware key `a` (Keystore alias
     * `xkey_key_a`) both have rows, as in LocalDeleteKeyExactIdTest. A share
     * of `a` waits for admission while [path] (both activities' deleteKey is
     * one [deleteKeyRow] call) deletes the `xkey_key_a` row: only the
     * software key goes, its ID is the one revoked, and the share of `a`
     * sends only while `a`'s material stands.
     */
    private suspend fun softwareRowDeletedWhileAShareOfTheHardwareKeyWaits(path: String) {
        val software = row("xkey_key_a")
        val hardware = row("a")
        val keystoreAliases = mutableSetOf("xkey_key_a")
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.resolveKeystoreAlias(any()) } answers {
            when (firstArg<String>()) {
                "a", "xkey_key_a" -> "xkey_key_a".takeIf { it in keystoreAliases }
                else -> null
            }
        }
        every { keystore.deleteByAlias(any()) } answers { keystoreAliases.remove(firstArg<String>()) }
        every { keystore.deleteGeneralKey(any()) } answers { keystoreAliases.remove("xkey_key_" + firstArg<String>()) }
        val softwareStore = mutableSetOf("xkey_key_a")
        val softwareKeys = mockk<SoftwareKeyStore>(relaxed = true)
        every { softwareKeys.contains(any()) } answers { firstArg<String>() in softwareStore }
        every { softwareKeys.delete(any()) } answers { softwareStore.remove(firstArg<String>()); Unit }
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.deleteByKeyId(any()) } answers { if (stored.remove(firstArg<String>()) != null) 1 else 0 }
        val revisionBefore = SharePermissionLedger.revision(software.keyId)

        val s = ScriptedMessageSender(router).also { it.succeedWith(accepted) }
        var checks = 0
        val waiting = DesktopKeyShare(
            session(s) {
                if (checks++ == 1) runBlocking { keyDao.deleteKeyRow(software, keystore, softwareKeys) }
                true
            },
            200
        )
        val out = waiting.send(SharePermissionLedger.baseline(hardware.keyId), hardware, null, pem, null, isShared, current)

        assertTrue("$path: the delete ran while the share waited", checks >= 2)
        assertFalse("$path removes the software key", "xkey_key_a" in softwareStore)
        assertFalse("$path deletes the software row", "xkey_key_a" in stored)
        assertTrue("$path leaves hardware key a's Keystore entry", "xkey_key_a" in keystoreAliases)
        assertTrue("$path leaves hardware key a's row", "a" in stored)
        assertTrue(
            "$path revokes the ID it removed",
            SharePermissionLedger.revision(software.keyId) > revisionBefore
        )
        if (out is DesktopKeyShare.Outcome.Sent) {
            assertTrue("$path: a's public half is sent only while a stands", "xkey_key_a" in keystoreAliases)
        } else {
            assertTrue("$path: a refused share sends nothing", s.sent.isEmpty())
        }
    }

    /**
     * FileEncryptor's ephemeral key lives at `xkey_key_ephemeral_<UUID>`;
     * key management opened during a long encryption has given it a row
     * (key ID `ephemeral_<UUID>`) and the user has enabled sharing. A share
     * of it waits for admission while the encryption completes and deletes
     * the key: the share is refused and nothing reaches the wire.
     */
    @Test
    fun `a discovered ephemeral key whose share waits while file encryption completes sends nothing`() = runTest {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.getPublicKeyDER(any()) } returns ByteArray(91) { 1 }
        coEvery { keystore.performECDH(any(), any()) } returns ByteArray(32) { 2 }
        val generated = CompletableFuture<String>()
        val release = CountDownLatch(1)
        val plaintext = object : InputStream() {
            override fun read(): Int = read(ByteArray(1), 0, 1)
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                release.await(5, TimeUnit.SECONDS)
                return -1
            }
        }
        val encryptor = FileEncryptor(keystore) { alias -> generated.complete(alias) }
        val encryption = thread {
            runBlocking { encryptor.encryptForRecipient(ByteArray(91) { 3 }, plaintext, ByteArrayOutputStream()) }
        }
        val keyId = generated.get(5, TimeUnit.SECONDS).removePrefix("xkey_key_")
        val ephemeral = row(keyId, source = "keystore")

        val s = ScriptedMessageSender(router).also { it.succeedWith(accepted) }
        var checks = 0
        val waiting = DesktopKeyShare(
            session(s) {
                if (checks++ == 1) {
                    release.countDown()
                    encryption.join(5_000)
                }
                true
            },
            200
        )
        val out = try {
            waiting.send(SharePermissionLedger.baseline(keyId), ephemeral, null, pem, null, isShared, current)
        } finally {
            release.countDown()
            encryption.join(5_000)
        }

        verify { keystore.deleteKey(keyId) }
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED), out)
        assertTrue("the deleted ephemeral key's public half never reaches the wire", s.sent.isEmpty())
    }
}
