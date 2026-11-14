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
package com.automatethethings.xkey.storage

import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.UserKeyKind

/**
 * What a key share may send for a key: its software material, or the public
 * key of its hardware key, or neither when the id holds no shareable key.
 */
class ShareableKey(val software: SoftwareKey?, val publicKeyPem: String?)

/**
 * The one read of a key a share sends (#255 review r4), for
 * `local.importSharedKey` and the key detail screen's desktop share alike.
 *
 * The namespace is resolved once ([KeystoreManager.exportKind]): a hardware
 * key shares its public key from either namespace, so a credential that
 * lives only under its credential alias shares like a general key. Both
 * reads run inside the use gate of that same kind ([KeyPolicyStore.withUsableKey]),
 * so a key whose delete was acknowledged is refused
 * ([KeyPolicyStore.KeyDeletedException]) and never read while its delete runs.
 * A general key beside a credential of its id shares its own key; a software
 * key beside a credential of its id names two keys and is shared as neither.
 *
 * @param softwareKey reads the id's software key (a general key kept outside the Keystore)
 */
suspend fun KeyPolicyStore.readShareable(
    keyId: String,
    keystore: KeystoreManager,
    softwareKey: (String) -> SoftwareKey?
): ShareableKey {
    val kind = keystore.exportKind(keyId)
    return withUsableKey(keyId, kind) {
        val software = softwareKey(keyId)
        when {
            software != null && kind != UserKeyKind.GENERAL -> {
                software.material.fill(0)
                ShareableKey(null, null)
            }
            software != null -> ShareableKey(software, null)
            else -> ShareableKey(null, keystore.getPublicKeyPEM(keyId, kind))
        }
    }
}
