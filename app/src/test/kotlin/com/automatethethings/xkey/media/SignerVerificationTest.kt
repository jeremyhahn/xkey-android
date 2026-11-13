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
package com.automatethethings.xkey.media

import android.util.Base64
import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The per-signer rule both verification screens share: a signer is verified
 * only when the stored content hash matches the file and the signature checks
 * against a public key we hold. A local key row without public key material
 * never matches, whatever its keyId: both the keyId comparison and the
 * fingerprint would come from the file under test.
 *
 * Real EC P-256 keys and SHA256withECDSA signatures; `android.util.Base64` and
 * `android.util.Log` are JVM stubs, so they are statically mocked.
 */
class SignerVerificationTest {

    private val contentHash = MediaHasher.hashBytes("the signed media".toByteArray())

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
        mockkStatic(Log::class)
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun fingerprint(keyPair: KeyPair): String = MediaHasher.hashBytes(keyPair.public.encoded)

    private fun entryFor(keyPair: KeyPair, fingerprint: String = fingerprint(keyPair)): SignatureEntry {
        val sig = Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyPair.private)
            update(SignatureVerifier.hexToBytes(contentHash))
        }.sign()
        return SignatureEntry(
            keyFingerprint = fingerprint,
            signerName = null,
            algorithm = "ES256",
            value = java.util.Base64.getEncoder().encodeToString(sig),
            timestamp = "2026-11-12T00:00:00Z"
        )
    }

    private fun verify(
        entry: SignatureEntry,
        contentHashMatches: Boolean = true,
        contact: SignerVerification.Contact? = null,
        localKeys: List<SignerVerification.LocalKey> = emptyList()
    ) = SignerVerification.verify(entry, contentHash, contentHashMatches, contact, localKeys)

    @Test
    fun `a local key with no public key never matches, so its signer is unknown`() {
        val attacker = newKeyPair()
        // The file names a fingerprint equal to a public-key-less row's keyId.
        val entry = entryFor(attacker, fingerprint = "key-without-public-material")
        val result = verify(
            entry,
            localKeys = listOf(SignerVerification.LocalKey("key-without-public-material", "My key", null))
        )
        assertEquals(SignerVerification.Status.UNKNOWN, result.status)
        assertEquals("key-without-publ...", result.displayName)
    }

    @Test
    fun `a matching local public key with a valid signature over a matching hash is verified`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair),
            localKeys = listOf(SignerVerification.LocalKey("k1", "My key", pair.public.encoded))
        )
        assertEquals(SignerVerification.Status.VERIFIED, result.status)
        assertEquals("My key", result.displayName)
    }

    @Test
    fun `a valid signature fails when the content hash does not match the file`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair),
            contentHashMatches = false,
            localKeys = listOf(SignerVerification.LocalKey("k1", "My key", pair.public.encoded))
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
    }

    @Test
    fun `a corrupted signature fails`() {
        val pair = newKeyPair()
        val good = entryFor(pair)
        val bytes = java.util.Base64.getDecoder().decode(good.value)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte()
        val corrupted = good.copy(value = java.util.Base64.getEncoder().encodeToString(bytes))
        val result = verify(
            corrupted,
            localKeys = listOf(SignerVerification.LocalKey("k1", "My key", pair.public.encoded))
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
    }

    @Test
    fun `a contact with a valid signature is verified under the contact name`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair),
            contact = SignerVerification.Contact("Alice", pair.public.encoded)
        )
        assertEquals(SignerVerification.Status.VERIFIED, result.status)
        assertEquals("Alice", result.displayName)
    }

    @Test
    fun `a contact whose key did not make the signature fails`() {
        val signer = newKeyPair()
        val contactKey = newKeyPair()
        val result = verify(
            entryFor(signer, fingerprint = fingerprint(contactKey)),
            contact = SignerVerification.Contact("Alice", contactKey.public.encoded)
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
    }

    @Test
    fun `a signer matching no contact and no local key is unknown`() {
        val signer = newKeyPair()
        val other = newKeyPair()
        val result = verify(
            entryFor(signer).copy(signerName = "Mallory"),
            localKeys = listOf(SignerVerification.LocalKey("k1", "My key", other.public.encoded))
        )
        assertEquals(SignerVerification.Status.UNKNOWN, result.status)
        assertEquals("Mallory", result.displayName)
    }

    /** A copied block from a signer nobody knows still fails on another file. */
    @Test
    fun `a content hash mismatch fails even when no signer matches`() {
        val stranger = newKeyPair()
        val result = verify(entryFor(stranger), contentHashMatches = false)
        assertEquals(SignerVerification.Status.FAILED, result.status)
    }

    /** The null-public-key row neither matches nor hides the mismatch. */
    @Test
    fun `a content hash mismatch fails for a signer whose local key has no public key`() {
        val attacker = newKeyPair()
        val entry = entryFor(attacker, fingerprint = "key-without-public-material")
        val result = verify(
            entry,
            contentHashMatches = false,
            localKeys = listOf(SignerVerification.LocalKey("key-without-public-material", "My key", null))
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
        assertEquals("key-without-publ...", result.displayName)
    }

    // The badge name comes from the key the signature was checked against;
    // the name the file embeds is only a claim (#196).

    @Test
    fun `a contact match verifies under the contact name and reports the embedded name as a claim`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair).copy(signerName = "Alice"),
            contact = SignerVerification.Contact("Bob", pair.public.encoded)
        )
        assertEquals(SignerVerification.Status.VERIFIED, result.status)
        assertEquals("Bob", result.displayName)
        assertEquals("Alice", result.claimedName)
    }

    @Test
    fun `a local key match with a differing embedded name verifies under the key label`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair).copy(signerName = "Alice"),
            localKeys = listOf(SignerVerification.LocalKey("k1", "My key", pair.public.encoded))
        )
        assertEquals(SignerVerification.Status.VERIFIED, result.status)
        assertEquals("My key", result.displayName)
        assertEquals("Alice", result.claimedName)
    }

    @Test
    fun `no match with an embedded name is unknown under that name with no claim`() {
        val result = verify(entryFor(newKeyPair()).copy(signerName = "Alice"))
        assertEquals(SignerVerification.Status.UNKNOWN, result.status)
        assertEquals("Alice", result.displayName)
        assertNull(result.claimedName)
    }

    @Test
    fun `a content hash mismatch with a matching contact fails under the contact name`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair).copy(signerName = "Alice"),
            contentHashMatches = false,
            contact = SignerVerification.Contact("Bob", pair.public.encoded)
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
        assertEquals("Bob", result.displayName)
        assertEquals("Alice", result.claimedName)
    }

    @Test
    fun `a content hash mismatch with a matching local key fails under the key label`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair).copy(signerName = "Alice"),
            contentHashMatches = false,
            localKeys = listOf(SignerVerification.LocalKey("k1", "My key", pair.public.encoded))
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
        assertEquals("My key", result.displayName)
    }

    @Test
    fun `a contact whose key did not make the signature fails under the contact name`() {
        val signer = newKeyPair()
        val contactKey = newKeyPair()
        val result = verify(
            entryFor(signer, fingerprint = fingerprint(contactKey)).copy(signerName = "Alice"),
            contact = SignerVerification.Contact("Bob", contactKey.public.encoded)
        )
        assertEquals(SignerVerification.Status.FAILED, result.status)
        assertEquals("Bob", result.displayName)
        assertEquals("Alice", result.claimedName)
    }

    @Test
    fun `an embedded name equal to the matched name gives no claim`() {
        val pair = newKeyPair()
        val result = verify(
            entryFor(pair).copy(signerName = "Bob"),
            contact = SignerVerification.Contact("Bob", pair.public.encoded)
        )
        assertEquals(SignerVerification.Status.VERIFIED, result.status)
        assertEquals("Bob", result.displayName)
        assertNull(result.claimedName)
    }
}
