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
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.protocol.KeyTypes
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The initiator QR names its key by the public-key fingerprint of the
 * selected row's own key, read in the namespace the row's key really lives
 * in ([initiatorKeyKind], from [KeystoreManager.keyRowAlias]): a phone-registered FIDO2 row is a
 * credential, a desktop-created FIDO2 row (`local.generateKey`) a general
 * key, every other row a general key. A credential and a general key may share
 * an id, each with its own public key, so neither row may borrow the other's.
 * A key whose public key cannot be read is refused, never named by its id
 * (CoSignInitiatorQrRefusalTest).
 */
class CoSignInitiatorFingerprintTest {

    private val credentialDer = ByteArray(91) { 5 }
    private val generalDer = ByteArray(91) { 6 }
    private val desktopFido2Der = ByteArray(91) { 7 }

    private val keystore = mockk<KeystoreManager> {
        every { keyRowAlias(any(), any(), any()) } answers { callOriginal() }
        // Both namespaces hold a key for SHARED_ID; resolution prefers the credential.
        every { resolveKeystoreAlias(SHARED_ID, any()) } returns CREDENTIAL_ALIAS
        every { resolveKeystoreAlias(MISSING_ID, any()) } returns null
        every { publicKeyDERAt(CREDENTIAL_ALIAS) } returns credentialDer
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(SHARED_ID)) } returns generalDer
        every { publicKeyDERAt(KeystoreManager.credentialAlias(MISSING_ID)) } returns null
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(MISSING_ID)) } returns null
        // A FIDO2 key the desktop created: only the general alias holds it.
        every { publicKeyDERAt(KeystoreManager.credentialAlias(DESKTOP_ID)) } returns null
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(DESKTOP_ID)) } returns desktopFido2Der
    }

    @Test
    fun `a FIDO2 row's initiator QR reads its credential`() {
        assertEquals(
            UserKeyKind.CREDENTIAL,
            initiatorKeyKind(keystore, SHARED_ID, KeyTypes.FIDO2, credentialDer)
        )
        assertEquals(
            "a row with no stored key still finds its credential",
            UserKeyKind.CREDENTIAL,
            initiatorKeyKind(keystore, SHARED_ID, KeyTypes.FIDO2, null)
        )
    }

    @Test
    fun `a desktop-created FIDO2 row stored under the general alias reads the general key`() {
        assertEquals(
            UserKeyKind.GENERAL,
            initiatorKeyKind(keystore, DESKTOP_ID, KeyTypes.FIDO2, desktopFido2Der)
        )
        assertEquals(
            UserKeyKind.GENERAL,
            initiatorKeyKind(keystore, DESKTOP_ID, KeyTypes.FIDO2, null)
        )
    }

    @Test
    fun `a FIDO2 row whose stored key is the general one never borrows a same-id credential's`() {
        assertEquals(
            UserKeyKind.GENERAL,
            initiatorKeyKind(keystore, SHARED_ID, KeyTypes.FIDO2, generalDer)
        )
    }

    @Test
    fun `a signing row sharing a credential's id reads its own general key`() {
        assertEquals(
            UserKeyKind.GENERAL,
            initiatorKeyKind(keystore, SHARED_ID, KeyTypes.SIGNING, credentialDer)
        )
    }

    @Test
    fun `tls and ssh rows read the general alias too`() {
        assertEquals(UserKeyKind.GENERAL, initiatorKeyKind(keystore, SHARED_ID, "tls", null))
        assertEquals(UserKeyKind.GENERAL, initiatorKeyKind(keystore, SHARED_ID, "ssh", null))
    }

    private companion object {
        const val SHARED_ID = "shared-1"
        val CREDENTIAL_ALIAS = KeystoreManager.credentialAlias(SHARED_ID)
        const val MISSING_ID = "missing-1"
        const val DESKTOP_ID = "desktop-fido2-1"
    }
}
