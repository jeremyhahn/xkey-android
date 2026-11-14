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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The camera permission has one choke point: [QrScannerActivity] asks for it
 * and reports a denial; launchers neither check CAMERA themselves nor read the
 * scanner result any way but [QrScanResult.from], so a launcher cannot skip
 * the denial feedback or open a camera without the grant.
 *
 * A source scan, so a new launcher that bypasses the gate fails here on the JVM.
 */
class QrScannerChokePointTest {

    private val sources: List<File> by lazy {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    private fun filesContaining(text: String): Set<String> =
        sources.filter { it.readText().contains(text) }.map { it.name }.toSet()

    @Test
    fun theScannerItselfRunsThePermissionGate() {
        val scanner = sources.single { it.name == "QrScannerActivity.kt" }.readText()
        assertTrue(scanner.contains("CameraPermissionGate.onCreate("))
        assertTrue(scanner.contains("CameraPermissionGate.onPermissionResult("))
        assertTrue(scanner.contains("RESULT_CAMERA_DENIED"))
    }

    @Test
    fun everyScannerLauncher_readsTheResultThroughQrScanResult() {
        val launchers = filesContaining("QrScannerActivity::class.java")
        assertEquals(setOf("CoSignActivity.kt", "OathActivity.kt"), launchers)
        val bypassing = launchers.filterNot { name ->
            sources.single { it.name == name }.readText().contains("QrScanResult.from(")
        }
        assertTrue("Launchers reading the scanner result without QrScanResult.from: $bypassing", bypassing.isEmpty())
    }

    @Test
    fun noScannerLauncher_checksTheCameraItself() {
        val launchers = filesContaining("QrScannerActivity::class.java")
        val checking = launchers.intersect(filesContaining("permission.CAMERA"))
        assertTrue("Launchers duplicating the scanner's CAMERA gate: $checking", checking.isEmpty())
    }

    @Test
    fun onlyAllowListedScreensBindTheCameraDirectly() {
        // ContactManagementActivity runs an inline scanner with its own CAMERA request.
        val direct = filesContaining("QrCodeScannerHelper(") - "QrCodeScannerHelper.kt"
        assertEquals(setOf("QrScannerActivity.kt", "ContactManagementActivity.kt"), direct)
    }
}
