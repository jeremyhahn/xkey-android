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

import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.PqcSoftwareKeyStore
import java.security.KeyPair

/**
 * The API level JVM [PivKeyManager] fixtures run on. Off a device
 * `Build.VERSION.SDK_INT` reads 0, below every [PivAlgorithm.minSdk], so a
 * manager left on the platform default refuses every generation before its
 * generator runs. 33 is the first level on which every [PivAlgorithm] is
 * available.
 */
internal const val SUPPORTED_TEST_SDK = 33

/**
 * The one way JVM tests build a [PivKeyManager]: on [SUPPORTED_TEST_SDK]
 * unless a test names another level, with every key and the curve 25519
 * hardware probe reading as [KeySecurityLevel.TEE] unless a test names
 * other readers.
 *
 * [generateKeyPair] null keeps the manager's Android Keystore generator, for
 * tests that route `KeyPairGenerator.getInstance(..., "AndroidKeyStore")` to a
 * fake ([FakePivKeystore.generatesOnNextCall]). [probeSecurityLevel] null
 * keeps the manager's own probe, which generates under a disposable alias
 * with [generateKeyPair] and reads it with [securityLevelOf]; its answers are
 * kept for the process until [PivKeyManager.forgetHardwareProbes].
 * [pqcStore] is the software ML-DSA store, as [PivKeyManager] takes it.
 */
internal fun testPivKeyManager(
    dao: PivSlotDao,
    generateKeyPair: ((alias: String, algorithm: PivAlgorithm) -> KeyPair)? = null,
    sdkInt: Int = SUPPORTED_TEST_SDK,
    securityLevelOf: (alias: String) -> KeySecurityLevel? = { KeySecurityLevel.TEE },
    probeSecurityLevel: ((algorithm: PivAlgorithm) -> KeySecurityLevel?)? = { KeySecurityLevel.TEE },
    pqcStore: PqcSoftwareKeyStore? = null
): PivKeyManager =
    if (generateKeyPair == null) {
        PivKeyManager(
            dao,
            sdkInt = sdkInt,
            securityLevelOf = securityLevelOf,
            probeSecurityLevel = probeSecurityLevel,
            pqcStore = pqcStore
        )
    } else {
        PivKeyManager(
            dao,
            generateKeyPair = generateKeyPair,
            sdkInt = sdkInt,
            securityLevelOf = securityLevelOf,
            probeSecurityLevel = probeSecurityLevel,
            pqcStore = pqcStore
        )
    }
