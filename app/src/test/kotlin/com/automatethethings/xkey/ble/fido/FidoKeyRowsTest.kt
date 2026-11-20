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
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Every key row the BLE authenticator builds comes from [FidoKeyRows], whose
 * legacy shareable flag agrees with the sharing policy. No other ble/fido
 * code builds or copies a KeyEntity, or sets shareable or sharingPolicy, so
 * none can store a flag that disagrees with its policy.
 */
class FidoKeyRowsTest {

    private val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    private val fido = root.walkTopDown()
        .filter { it.isFile && it.extension == "kt" && it.path.replace('\\', '/').contains("/xkey/ble/fido/") }
        .toList()
    private val others = fido.filter { it.name != "FidoKeyRows.kt" }
    private val rows = fido.single { it.name == "FidoKeyRows.kt" }.readText()

    private fun offenders(pattern: Regex) =
        others.filter { pattern.containsMatchIn(it.readText()) }.map { it.name }

    @Test
    fun `the shareable flag of a built row agrees with every sharing policy`() {
        for (policy in SharingPolicyType.entries) {
            val row = FidoKeyRows.passkey(
                keyId = "k", label = "Example", publicKeyCose = byteArrayOf(1), rpId = "example.com",
                rpName = "Example", userId = "dQ", userName = "alice", userDisplayName = "Alice",
                discoverable = true, createdAt = 0L, policy = policy,
                securityLevel = KeySecurityLevel.TEE
            )
            assertEquals(policy, row.sharingPolicy)
            assertEquals(policy.name, policy != SharingPolicyType.PRIVATE, row.shareable)
        }
    }

    @Test
    fun `no other ble fido code builds a KeyEntity`() {
        assertEquals(emptyList<String>(), offenders(Regex("""\bKeyEntity\s*\(""")))
        assertEquals("one construction", 1, Regex("""\bKeyEntity\s*\(""").findAll(rows).count())
    }

    @Test
    fun `no other ble fido code copies a row or sets shareable or sharingPolicy`() {
        assertEquals(emptyList<String>(), offenders(Regex("""\.copy\s*\(""")))
        assertEquals(emptyList<String>(), offenders(Regex("""\bshareable\s*=(?!=)""")))
        assertEquals(emptyList<String>(), offenders(Regex("""\bsharingPolicy\s*=(?!=)""")))
    }

    @Test
    fun `the one construction derives shareable from its policy`() {
        assertEquals(1, Regex("""\bshareable\s*=(?!=)""").findAll(rows).count())
        assertEquals(true, rows.contains("shareable = shareableFor(policy)"))
        assertEquals(true, rows.contains("sharingPolicy = policy"))
    }
}
