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
import org.junit.Test

/**
 * The scanner's camera permission gate and the result every launcher reads:
 * a fresh install (or a revoked grant) asks for CAMERA, a denial finishes the
 * scanner with [QrScannerActivity.RESULT_CAMERA_DENIED], and the launcher maps
 * that to [QrScanResult.CameraDenied] rather than a silent cancel.
 */
class QrScannerPermissionGateTest {

    @Test
    fun aGrantedCamera_startsTheCamera() {
        assertEquals(
            CameraPermissionGate.Step.START_CAMERA,
            CameraPermissionGate.onCreate(granted = true, requestInFlight = false)
        )
    }

    @Test
    fun aMissingGrant_asksForTheCamera() {
        assertEquals(
            CameraPermissionGate.Step.REQUEST_PERMISSION,
            CameraPermissionGate.onCreate(granted = false, requestInFlight = false)
        )
    }

    @Test
    fun aRecreatedScanner_withTheRequestStillOpen_doesNotAskTwice() {
        assertEquals(
            CameraPermissionGate.Step.AWAIT_PERMISSION,
            CameraPermissionGate.onCreate(granted = false, requestInFlight = true)
        )
    }

    @Test
    fun aGrantArrivingWhileTheRequestIsOpen_startsTheCamera() {
        assertEquals(
            CameraPermissionGate.Step.START_CAMERA,
            CameraPermissionGate.onCreate(granted = true, requestInFlight = true)
        )
    }

    @Test
    fun theUserGranting_startsTheCamera() {
        assertEquals(CameraPermissionGate.Step.START_CAMERA, CameraPermissionGate.onPermissionResult(true))
    }

    @Test
    fun theUserDenying_finishesWithTheDenial() {
        assertEquals(CameraPermissionGate.Step.FINISH_DENIED, CameraPermissionGate.onPermissionResult(false))
    }

    @Test
    fun theDenialResult_isNotACancelOrASuccess() {
        val denied = QrScannerActivity.RESULT_CAMERA_DENIED
        assert(denied != android.app.Activity.RESULT_OK && denied != android.app.Activity.RESULT_CANCELED)
        assertEquals(QrScanResult.CameraDenied, QrScanResult.from(denied, null))
        assertEquals(QrScanResult.CameraDenied, QrScanResult.from(denied, "{\"v\":1}"))
    }

    @Test
    fun aScannedValue_isReturnedOnlyWithOk() {
        assertEquals(QrScanResult.Scanned("otpauth://x"), QrScanResult.from(android.app.Activity.RESULT_OK, "otpauth://x"))
        assertEquals(QrScanResult.Cancelled, QrScanResult.from(android.app.Activity.RESULT_OK, null))
        assertEquals(QrScanResult.Cancelled, QrScanResult.from(android.app.Activity.RESULT_CANCELED, "otpauth://x"))
    }
}
