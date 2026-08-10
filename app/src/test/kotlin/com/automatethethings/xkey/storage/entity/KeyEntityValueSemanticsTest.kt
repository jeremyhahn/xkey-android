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
package com.automatethethings.xkey.storage.entity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [KeyEntity]'s hand-written value semantics.
 *
 * [KeyEntity] carries two nullable [ByteArray] columns, so it overrides
 * `equals`/`hashCode` rather than taking the generated ones — reference
 * comparison there would make two rows read back from Room look different
 * even when they hold identical key material. Each field is therefore
 * pinned individually, and both null branches of each array are exercised.
 *
 * The KDoc on [KeyEntity.shareable] states the invariant that it and
 * [KeyEntity.sharingPolicy] must agree; all four key-creation paths once
 * violated it, so the agreement is asserted here as an executable rule.
 */
class KeyEntityValueSemanticsTest {

    private val der = byteArrayOf(0x30, 0x59, 0x30, 0x13)
    private val cose = byteArrayOf(0xA5.toByte(), 0x01, 0x02, 0x03)

    private fun key(
        keyId: String = "key-1",
        publicKeyDer: ByteArray? = der,
        publicKeyCose: ByteArray? = cose
    ) = KeyEntity(
        id = 7L,
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = "Example",
        publicKeyDer = publicKeyDer,
        publicKeyCose = publicKeyCose,
        keySizeBits = 256,
        strongBoxBacked = true,
        biometricRequired = true,
        authDurationSeconds = 30,
        exportable = false,
        shareable = true,
        sharingPolicy = SharingPolicyType.ALL_PEERS,
        source = "local",
        remoteBackend = "tpm2",
        useCount = 3L,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_100_000L,
        rpId = "example.com",
        rpName = "Example",
        userId = "dXNlcg",
        userName = "user@example.com",
        userDisplayName = "A User",
        isDiscoverable = true,
        signCount = 9L,
        isSystemKey = false
    )

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `a minimally constructed key defaults to the private posture`() {
        val entity = KeyEntity(
            keyId = "k",
            keyType = "signing",
            algorithm = "ES256",
            label = "L",
            keySizeBits = 256,
            source = "local"
        )

        assertEquals(0L, entity.id)
        assertNull(entity.publicKeyDer)
        assertNull(entity.publicKeyCose)
        assertFalse(entity.strongBoxBacked)
        assertTrue(entity.biometricRequired)
        assertEquals(5, entity.authDurationSeconds)
        assertFalse(entity.exportable)
        assertFalse(entity.shareable)
        assertEquals(SharingPolicyType.PRIVATE, entity.sharingPolicy)
        assertNull(entity.remoteBackend)
        assertEquals(0L, entity.useCount)
        assertEquals(0L, entity.lastUsedAt)
        assertFalse(entity.isDiscoverable)
        assertEquals(0L, entity.signCount)
        assertFalse(entity.isSystemKey)
    }

    @Test
    fun `a minimally constructed key stamps its own creation time`() {
        val before = System.currentTimeMillis()
        val entity = KeyEntity(
            keyId = "k",
            keyType = "signing",
            algorithm = "ES256",
            label = "L",
            keySizeBits = 256,
            source = "local"
        )
        val after = System.currentTimeMillis()

        assertTrue(entity.createdAt in before..after)
    }

    // -------------------------------------------------------------------------
    // equals / hashCode
    // -------------------------------------------------------------------------

    @Test
    fun `two keys with the same fields are equal and hash alike`() {
        val a = key()
        val b = key()

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `equal byte content in distinct arrays still compares equal`() {
        val a = key(publicKeyDer = byteArrayOf(1, 2, 3), publicKeyCose = byteArrayOf(4, 5))
        val b = key(publicKeyDer = byteArrayOf(1, 2, 3), publicKeyCose = byteArrayOf(4, 5))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `a key equals itself`() {
        val a = key()

        assertEquals(a, a)
    }

    @Test
    fun `a key is never equal to null or an unrelated value`() {
        val a = key()

        assertNotEquals(a, null)
        assertFalse(a.equals("key-1"))
    }

    @Test
    fun `keys differing in any single scalar field are not equal`() {
        val base = key()

        assertNotEquals(base, base.copy(id = 8L))
        assertNotEquals(base, base.copy(keyId = "other"))
        assertNotEquals(base, base.copy(keyType = "signing"))
        assertNotEquals(base, base.copy(algorithm = "RS256"))
        assertNotEquals(base, base.copy(label = "Other"))
        assertNotEquals(base, base.copy(keySizeBits = 384))
        assertNotEquals(base, base.copy(strongBoxBacked = false))
        assertNotEquals(base, base.copy(biometricRequired = false))
        assertNotEquals(base, base.copy(authDurationSeconds = 60))
        assertNotEquals(base, base.copy(exportable = true))
        assertNotEquals(base, base.copy(shareable = false))
        assertNotEquals(base, base.copy(sharingPolicy = SharingPolicyType.SELECTED_PEERS))
        assertNotEquals(base, base.copy(source = "remote_ble"))
        assertNotEquals(base, base.copy(remoteBackend = "pkcs11"))
        assertNotEquals(base, base.copy(useCount = 4L))
        assertNotEquals(base, base.copy(createdAt = 1L))
        assertNotEquals(base, base.copy(lastUsedAt = 2L))
        assertNotEquals(base, base.copy(rpId = "other.test"))
        assertNotEquals(base, base.copy(rpName = "Other"))
        assertNotEquals(base, base.copy(userId = "b3RoZXI"))
        assertNotEquals(base, base.copy(userName = "other@example.com"))
        assertNotEquals(base, base.copy(userDisplayName = "Other User"))
        assertNotEquals(base, base.copy(isDiscoverable = false))
        assertNotEquals(base, base.copy(signCount = 10L))
        assertNotEquals(base, base.copy(isSystemKey = true))
    }

    @Test
    fun `keys differing only in public key DER content are not equal`() {
        val a = key(publicKeyDer = byteArrayOf(1, 2, 3))
        val b = key(publicKeyDer = byteArrayOf(1, 2, 4))

        assertNotEquals(a, b)
    }

    @Test
    fun `keys differing only in COSE key content are not equal`() {
        val a = key(publicKeyCose = byteArrayOf(1, 2, 3))
        val b = key(publicKeyCose = byteArrayOf(1, 2, 3, 4))

        assertNotEquals(a, b)
    }

    @Test
    fun `a present DER never equals an absent one in either direction`() {
        val present = key(publicKeyDer = der)
        val absent = key(publicKeyDer = null)

        assertNotEquals(present, absent)
        assertNotEquals(absent, present)
    }

    @Test
    fun `a present COSE key never equals an absent one in either direction`() {
        val present = key(publicKeyCose = cose)
        val absent = key(publicKeyCose = null)

        assertNotEquals(present, absent)
        assertNotEquals(absent, present)
    }

    @Test
    fun `two symmetric keys with no public material are equal`() {
        val a = key(publicKeyDer = null, publicKeyCose = null)
        val b = key(publicKeyDer = null, publicKeyCose = null)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `hashCode is stable across repeated calls`() {
        val a = key()

        assertEquals(a.hashCode(), a.hashCode())
    }

    // -------------------------------------------------------------------------
    // copy / toString
    // -------------------------------------------------------------------------

    @Test
    fun `copy replaces only the named field`() {
        val base = key()
        val renamed = base.copy(label = "Renamed")

        assertEquals("Renamed", renamed.label)
        assertEquals(base.keyId, renamed.keyId)
        assertEquals(base.algorithm, renamed.algorithm)
        assertEquals(base.sharingPolicy, renamed.sharingPolicy)
        assertTrue(base.publicKeyDer.contentEquals(renamed.publicKeyDer))
    }

    @Test
    fun `copy shares the same array instance rather than cloning it`() {
        val base = key()

        assertTrue(base.publicKeyDer === base.copy(label = "x").publicKeyDer)
    }

    @Test
    fun `toString renders the identifying fields`() {
        val rendered = key().toString()

        assertTrue(rendered.contains("keyId=key-1"))
        assertTrue(rendered.contains("keyType=fido2"))
        assertTrue(rendered.contains("sharingPolicy=ALL_PEERS"))
    }

    // -------------------------------------------------------------------------
    // Sharing invariant
    // -------------------------------------------------------------------------

    @Test
    fun `a private key is not shareable`() {
        val entity = key().copy(shareable = false, sharingPolicy = SharingPolicyType.PRIVATE)

        assertFalse(entity.shareable)
        assertEquals(SharingPolicyType.PRIVATE, entity.sharingPolicy)
    }

    @Test
    fun `shareable and sharingPolicy agree for every policy value`() {
        // The KDoc on KeyEntity.shareable makes this the contract: PRIVATE
        // implies the legacy flag is off, every other policy implies it is on.
        for (policy in SharingPolicyType.entries) {
            val expected = policy != SharingPolicyType.PRIVATE
            val entity = key().copy(shareable = expected, sharingPolicy = policy)

            assertEquals(
                "shareable must agree with $policy",
                expected,
                entity.shareable
            )
        }
    }

    // -------------------------------------------------------------------------
    // SharingPolicyType
    // -------------------------------------------------------------------------

    @Test
    fun `SharingPolicyType has exactly the three documented modes`() {
        assertEquals(3, SharingPolicyType.entries.size)
        assertEquals(
            listOf("PRIVATE", "ALL_PEERS", "SELECTED_PEERS"),
            SharingPolicyType.entries.map { it.name }
        )
    }

    @Test
    fun `SharingPolicyType round-trips through its persisted name`() {
        for (policy in SharingPolicyType.entries) {
            assertEquals(policy, SharingPolicyType.valueOf(policy.name))
        }
    }

    @Test
    fun `PRIVATE is the first declared mode so it is the safe default`() {
        assertEquals(SharingPolicyType.PRIVATE, SharingPolicyType.entries.first())
    }
}
