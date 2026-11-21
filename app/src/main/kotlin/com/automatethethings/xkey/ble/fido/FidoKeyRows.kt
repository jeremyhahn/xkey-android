/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.ble.fido

import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType

/**
 * The one place the BLE authenticator builds a key row. The legacy
 * [KeyEntity.shareable] flag, which local.listKeys and local.getKeyInfo still
 * report, follows the row's [KeyEntity.sharingPolicy] as [KeyEntity]
 * documents: PRIVATE is unshareable, ALL_PEERS and SELECTED_PEERS are
 * shareable. No other ble/fido code builds or copies a [KeyEntity] or sets
 * either field (FidoKeyRowsTest checks the sources).
 */
internal object FidoKeyRows {

    /** The legacy shareable flag that agrees with [policy]. */
    fun shareableFor(policy: SharingPolicyType): Boolean = policy != SharingPolicyType.PRIVATE

    /**
     * The key row of a passkey a BLE client registers: an ES256 Keystore key
     * that is not auth-bound and not exportable, shared under [policy].
     * [securityLevel] is where the generated key really lives, read from its
     * KeyInfo ([com.automatethethings.xkey.crypto.KeystoreManager.credentialSecurityLevel]):
     * StrongBox is preferred, and a phone without it generates in the TEE.
     */
    fun passkey(
        keyId: String,
        label: String,
        publicKeyCose: ByteArray,
        rpId: String,
        rpName: String,
        userId: String,
        userName: String?,
        userDisplayName: String?,
        discoverable: Boolean,
        createdAt: Long,
        policy: SharingPolicyType,
        securityLevel: KeySecurityLevel
    ): KeyEntity = KeyEntity(
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = label,
        publicKeyCose = publicKeyCose,
        keySizeBits = 256,
        strongBoxBacked = securityLevel == KeySecurityLevel.STRONGBOX,
        biometricRequired = false,
        authDurationSeconds = -1,
        exportable = false,
        shareable = shareableFor(policy),
        source = "local",
        createdAt = createdAt,
        rpId = rpId,
        rpName = rpName,
        userId = userId,
        userName = userName,
        userDisplayName = userDisplayName,
        isDiscoverable = discoverable,
        signCount = 0,
        sharingPolicy = policy
    )
}
