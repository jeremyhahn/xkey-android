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
package com.automatethethings.xkey.protocol

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every share path takes its permission from [SharePermission], the one
 * decision. Fails when any production source outside it reads a peer grant
 * or the pending-revocation set to decide a share, sends a key to a desktop
 * outside DesktopKeyShare, or when a share path stops going through it.
 */
class SharePermissionChokePointTest {

    private val mainSources: File =
        listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }

    /** Production source files with comment lines removed, keyed by path relative to [mainSources]. */
    private val sources: Map<String, String> by lazy {
        mainSources.walkTopDown().filter { it.isFile && it.extension == "kt" }.associate { file ->
            file.relativeTo(mainSources).invariantSeparatorsPath to file.readLines()
                .filterNot { line -> line.trimStart().let { it.startsWith("*") || it.startsWith("/*") || it.startsWith("//") } }
                .joinToString("\n")
        }
    }

    private fun filesCalling(call: String): Set<String> =
        sources.filterValues { call in it }.keys.map { it.substringAfterLast('/') }.toSet()

    @Test
    fun onlySharePermissionReadsAPeerGrant() {
        assertEquals(
            "a share decision outside SharePermission reads key_sharing_policies",
            setOf("SharePermission.kt"),
            filesCalling(".isKeySharedWithPeer(")
        )
        assertEquals(
            "a share decision outside SharePermission reads a grant row",
            setOf("SharePermission.kt"),
            filesCalling(".isPeerGranted(")
        )
    }

    @Test
    fun onlySharePermissionEnforcesAPendingSharingEdit() {
        // KeySharingPeers' own definitions are the only other mention.
        assertEquals(
            setOf("SharePermission.kt"),
            (filesCalling(".isWithdrawalPending(") + filesCalling(".enforcedPolicy(")) - "KeySharingPeers.kt"
        )
    }

    @Test
    fun onlySharePermissionReadsThePendingRevocationSetForAShare() {
        // The repository's own definition is the only other mention.
        assertEquals(
            setOf("SharePermission.kt"),
            filesCalling(".isRevocationPending(") - "PairedDeviceRepository.kt"
        )
    }

    @Test
    fun onlyDesktopKeyShareSendsAKeyToADesktop() {
        // RemoteShareClient.kt holds the client and DesktopKeyShare, which
        // sends only after DesktopShareGate (and so SharePermission) admits it.
        assertEquals(setOf("RemoteShareClient.kt"), filesCalling(".sharePublicKey("))
        assertEquals(emptySet<String>(), filesCalling(".shareSymmetric(") - "RemoteShareClient.kt")
    }

    @Test
    fun everySharePathGoesThroughSharePermission() {
        val handler = sources.getValue("com/automatethethings/xkey/protocol/Handler.kt")
        assertTrue("the inbound handlers decide through SharePermission", "sharePermission.canShare(" in handler)

        val gate = sources.getValue("com/automatethethings/xkey/remote/RemoteShareClient.kt")
        assertTrue("DesktopShareGate decides through SharePermission", "permission.canShare(" in gate)

        val sheet = sources.getValue("com/automatethethings/xkey/ui/KeySharingBottomSheet.kt")
        assertTrue(
            "the key-sharing sheet builds SharePermission over the paired-device repository",
            "SharePermission(keySharingPolicyDao, pairedDeviceRepository)" in sheet
        )
    }
}
