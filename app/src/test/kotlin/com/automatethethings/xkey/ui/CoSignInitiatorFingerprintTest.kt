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

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.MediaHasher
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The initiator QR names its key by the public-key fingerprint of the
 * selected row's own key: a FIDO2 row reads the credential alias, every other
 * row the general alias. A credential and a general key may share an id, each
 * with its own public key, so neither row may borrow the other's.
 */
class CoSignInitiatorFingerprintTest {

    private val credentialDer = ByteArray(91) { 5 }
    private val generalDer = ByteArray(91) { 6 }

    private val keystore = mockk<KeystoreManager> {
        // Both namespaces hold a key for SHARED_ID; resolution prefers the credential.
        every { resolveKeystoreAlias(SHARED_ID) } returns CREDENTIAL_ALIAS
        every { resolveKeystoreAlias(MISSING_ID) } returns null
        every { publicKeyDERAt(CREDENTIAL_ALIAS) } returns credentialDer
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(SHARED_ID)) } returns generalDer
        every { publicKeyDERAt("xkey_credential_$MISSING_ID") } returns null
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(MISSING_ID)) } returns null
    }

    @Test
    fun `a FIDO2 row's initiator QR carries its credential's fingerprint`() {
        assertEquals(MediaHasher.hashBytes(credentialDer), initiatorFingerprint(keystore, SHARED_ID, "fido2"))
    }

    @Test
    fun `a signing row sharing a credential's id carries its own general key's fingerprint`() {
        assertEquals(MediaHasher.hashBytes(generalDer), initiatorFingerprint(keystore, SHARED_ID, "signing"))
    }

    @Test
    fun `tls and ssh rows read the general alias too`() {
        assertEquals(MediaHasher.hashBytes(generalDer), initiatorFingerprint(keystore, SHARED_ID, "tls"))
        assertEquals(MediaHasher.hashBytes(generalDer), initiatorFingerprint(keystore, SHARED_ID, "ssh"))
    }

    @Test
    fun `a key with no stored public key is named by its id`() {
        assertEquals(MISSING_ID, initiatorFingerprint(keystore, MISSING_ID, "signing"))
        assertEquals(MISSING_ID, initiatorFingerprint(keystore, MISSING_ID, "fido2"))
    }

    private companion object {
        const val SHARED_ID = "shared-1"
        const val CREDENTIAL_ALIAS = "xkey_credential_$SHARED_ID"
        const val MISSING_ID = "missing-1"
    }
}
