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

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.automatethethings.xkey.R
import com.automatethethings.xkey.qr.QrCodeScannerHelper
import com.google.android.material.snackbar.Snackbar
import org.json.JSONException
import org.json.JSONObject

/**
 * The one place the app asks for CAMERA before scanning: every launcher starts
 * this activity and reads its result through [QrScanResult.from]. A denial
 * finishes with [RESULT_CAMERA_DENIED] so the launcher can say why.
 */
class QrScannerActivity : AppCompatActivity() {

    private lateinit var scannerHelper: QrCodeScannerHelper
    private var permissionRequestInFlight = false

    private val cameraPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        permissionRequestInFlight = false
        apply(CameraPermissionGate.onPermissionResult(granted))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scanner)

        permissionRequestInFlight = savedInstanceState?.getBoolean(STATE_PERMISSION_REQUEST_IN_FLIGHT) ?: false
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        apply(CameraPermissionGate.onCreate(granted, permissionRequestInFlight))
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_PERMISSION_REQUEST_IN_FLIGHT, permissionRequestInFlight)
    }

    private fun apply(step: CameraPermissionGate.Step) {
        when (step) {
            CameraPermissionGate.Step.START_CAMERA -> startCamera()
            CameraPermissionGate.Step.REQUEST_PERMISSION -> {
                permissionRequestInFlight = true
                cameraPermission.launch(Manifest.permission.CAMERA)
            }
            CameraPermissionGate.Step.AWAIT_PERMISSION -> Unit
            CameraPermissionGate.Step.FINISH_DENIED -> {
                setResult(RESULT_CAMERA_DENIED)
                finish()
            }
        }
    }

    private fun startCamera() {
        if (::scannerHelper.isInitialized) return
        val previewView = findViewById<PreviewView>(R.id.previewView)

        scannerHelper = QrCodeScannerHelper(
            context = this,
            lifecycleOwner = this,
            previewView = previewView,
            onResult = { value -> onQrScanned(value) }
        )

        scannerHelper.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::scannerHelper.isInitialized) {
            scannerHelper.stop()
        }
    }

    private val payloadKind: QrPayloadKind by lazy {
        QrPayloadKind.fromExtra(intent?.getStringExtra(EXTRA_PAYLOAD_KIND))
    }

    private fun onQrScanned(value: String) {
        if (QrPayloadFilter.accepts(value, payloadKind)) {
            val resultIntent = Intent().apply {
                putExtra(EXTRA_SCANNED_URI, value)
            }
            setResult(RESULT_OK, resultIntent)
            finish()
        } else {
            runOnUiThread {
                Snackbar.make(
                    findViewById(R.id.snackbarAnchor),
                    when (payloadKind) {
                        QrPayloadKind.OTPAUTH -> R.string.oath_qr_invalid
                        QrPayloadKind.COSIGN -> R.string.cosign_qr_invalid
                    },
                    Snackbar.LENGTH_SHORT
                ).show()
                // Restart scanning for the next QR code
                scannerHelper.start()
            }
        }
    }

    companion object {
        const val EXTRA_SCANNED_URI = "scanned_uri"

        /** A [QrPayloadKind] name; absent or unknown means [QrPayloadKind.OTPAUTH]. */
        const val EXTRA_PAYLOAD_KIND = "payload_kind"

        /** The scanner finished because the user refused CAMERA. */
        const val RESULT_CAMERA_DENIED = RESULT_FIRST_USER

        private const val STATE_PERMISSION_REQUEST_IN_FLIGHT = "permission_request_in_flight"
    }
}

/** What [QrScannerActivity] does about the camera permission. Pure: JVM-testable. */
object CameraPermissionGate {
    enum class Step { START_CAMERA, REQUEST_PERMISSION, AWAIT_PERMISSION, FINISH_DENIED }

    /**
     * On create: scan when granted; otherwise ask, unless a request from an
     * earlier instance is still open (its answer is redelivered to this one).
     */
    fun onCreate(granted: Boolean, requestInFlight: Boolean): Step = when {
        granted -> Step.START_CAMERA
        requestInFlight -> Step.AWAIT_PERMISSION
        else -> Step.REQUEST_PERMISSION
    }

    fun onPermissionResult(granted: Boolean): Step =
        if (granted) Step.START_CAMERA else Step.FINISH_DENIED
}

/** A [QrScannerActivity] result as every launcher reads it. */
sealed interface QrScanResult {
    data class Scanned(val value: String) : QrScanResult
    data object CameraDenied : QrScanResult
    data object Cancelled : QrScanResult

    companion object {
        /** [scannedValue] is the [QrScannerActivity.EXTRA_SCANNED_URI] extra, if any. */
        fun from(resultCode: Int, scannedValue: String?): QrScanResult = when {
            resultCode == QrScannerActivity.RESULT_CAMERA_DENIED -> CameraDenied
            resultCode == android.app.Activity.RESULT_OK && scannedValue != null -> Scanned(scannedValue)
            else -> Cancelled
        }

        /** Reads an activity result from the scanner. */
        fun from(result: ActivityResult): QrScanResult =
            from(result.resultCode, result.data?.getStringExtra(QrScannerActivity.EXTRA_SCANNED_URI))
    }
}

/** The payload kind a [QrScannerActivity] caller asks for. */
enum class QrPayloadKind {
    /** An `otpauth://` URI (the default, for OATH enrolment). */
    OTPAUTH,

    /** A co-sign request or response JSON object. */
    COSIGN;

    companion object {
        /** The kind named by the intent extra; otpauth when it is absent or unknown. */
        fun fromExtra(value: String?): QrPayloadKind =
            entries.firstOrNull { it.name == value } ?: OTPAUTH
    }
}

/** Decides whether a scanned QR value is the kind the caller asked for. Pure: JVM-testable. */
object QrPayloadFilter {
    fun accepts(value: String, kind: QrPayloadKind): Boolean = when (kind) {
        QrPayloadKind.OTPAUTH -> value.startsWith("otpauth://")
        QrPayloadKind.COSIGN -> isCoSignPayload(value)
    }

    private fun isCoSignPayload(value: String): Boolean {
        val trimmed = value.trim()
        if (!trimmed.startsWith("{")) return false
        return try {
            JSONObject(trimmed).has("v")
        } catch (_: JSONException) {
            false
        }
    }
}
