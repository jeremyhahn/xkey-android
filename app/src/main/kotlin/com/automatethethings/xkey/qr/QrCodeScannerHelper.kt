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
package com.automatethethings.xkey.qr

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.util.Size
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

class QrCodeScannerHelper(
    private val context: Context,
    private val lifecycleOwner: LifecycleOwner,
    private val previewView: PreviewView,
    private val onResult: (String) -> Unit,
    frameSource: FrameSource? = null,
    scannerFactory: (() -> BarcodeScanner)? = null
) {
    /**
     * Where the frames come from: the back camera, decoded by ML Kit, unless
     * a test passes a source of its own.
     */
    interface FrameSource {
        /** Starts delivering frames to [analyzer]; called by every [start]. */
        fun bind(analyzer: (Frame) -> Unit)

        /** Stops delivering frames. */
        fun unbind()
    }

    /** One camera frame. */
    interface Frame {
        /**
         * Decodes the frame and calls back once: [onBarcodes] with the raw
         * values of the barcodes found (possibly none), or [onFailure]. The
         * frame is released once decoded.
         */
        fun decode(onBarcodes: (List<String?>) -> Unit, onFailure: () -> Unit)

        /** Releases a frame that is not decoded. */
        fun close()
    }

    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val frames: FrameSource = frameSource ?: CameraFrames()

    /**
     * Makes the ML Kit client: the given factory, else the real client when
     * the frames are the camera's. A frame source of a test's own decodes its
     * frames itself and, without a factory, needs no client.
     */
    private val scannerFactory: (() -> BarcodeScanner)? =
        scannerFactory ?: if (frameSource == null) {
            { BarcodeScanning.getClient() }
        } else {
            null
        }

    /** Guards [scanner], [decoding] and [stopped]. */
    private val lock = Any()

    /**
     * The one ML Kit client, made on the first [start] and kept across the
     * restarts that follow a rejected code; [stop] closes it.
     */
    private var scanner: BarcodeScanner? = null

    /** A frame's decode has not called back yet: [stop] leaves the client open for it. */
    private var decoding = false

    /** [stop] ran: frames are dropped and nothing more is delivered. */
    private var stopped = false

    /** A frame is being decoded, or a value was delivered: later frames are dropped. */
    @Volatile
    private var processing = false

    fun hasCameraPermission(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    /** Starts scanning; after a delivered value, scans again for the next one. */
    fun start() {
        synchronized(lock) {
            if (stopped) return
            if (scanner == null) scanner = scannerFactory?.invoke()
            processing = false
        }
        frames.bind(::analyze)
    }

    /**
     * Stops scanning for good: unbinds the frames and closes the client, at
     * once or, with a decode in flight, when that decode calls back.
     */
    fun stop() {
        val closeNow = synchronized(lock) {
            if (stopped) return
            stopped = true
            !decoding
        }
        frames.unbind()
        cameraExecutor.shutdown()
        if (closeNow) closeScanner()
    }

    private fun closeScanner() {
        val scanner = synchronized(lock) { this.scanner.also { this.scanner = null } } ?: return
        scanner.close()
    }

    /** Ends the decode in flight; false once [stop] ran, the client then closed here. */
    private fun endDecode(): Boolean {
        val running = synchronized(lock) {
            decoding = false
            !stopped
        }
        if (!running) closeScanner()
        return running
    }

    private fun analyze(frame: Frame) {
        val take = synchronized(lock) {
            if (processing || stopped) {
                false
            } else {
                processing = true
                decoding = true
                true
            }
        }
        if (!take) {
            frame.close()
            return
        }
        frame.decode(
            onBarcodes = { values ->
                if (endDecode()) {
                    val value = values.firstOrNull { it != null }
                    if (value != null) {
                        // Unbind first: onResult may call start() to scan again.
                        frames.unbind()
                        onResult(value)
                    } else {
                        processing = false
                    }
                }
            },
            onFailure = { if (endDecode()) processing = false }
        )
    }

    /** The client for a frame's decode: null only after [stop] closed it. */
    private fun activeScanner(): BarcodeScanner? = synchronized(lock) { scanner }

    /** The back camera, its frames decoded by ML Kit. */
    private inner class CameraFrames : FrameSource {
        private var cameraProvider: ProcessCameraProvider? = null

        override fun bind(analyzer: (Frame) -> Unit) {
            val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
            cameraProviderFuture.addListener({
                // A stop() before the provider is ready leaves the camera unbound.
                if (synchronized(lock) { stopped }) return@addListener
                val provider = cameraProviderFuture.get()
                cameraProvider = provider
                bindCamera(provider, analyzer)
            }, ContextCompat.getMainExecutor(context))
        }

        override fun unbind() {
            cameraProvider?.unbindAll()
        }
    }

    @OptIn(ExperimentalGetImage::class)
    private fun bindCamera(cameraProvider: ProcessCameraProvider, analyzer: (Frame) -> Unit) {
        val preview = Preview.Builder().build().also {
            it.surfaceProvider = previewView.surfaceProvider
        }

        val imageAnalysis = ImageAnalysis.Builder()
            .setTargetResolution(Size(1280, 720))
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()

        imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
            val mediaImage = imageProxy.image
            if (mediaImage == null) {
                imageProxy.close()
                return@setAnalyzer
            }
            analyzer(object : Frame {
                override fun decode(onBarcodes: (List<String?>) -> Unit, onFailure: () -> Unit) {
                    val client = activeScanner()
                    if (client == null) {
                        imageProxy.close()
                        onFailure()
                        return
                    }
                    val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
                    // Exactly one callback, a cancel included, so stop() can close the client.
                    client.process(image)
                        .addOnSuccessListener { barcodes -> onBarcodes(barcodes.map { it.rawValue }) }
                        .addOnFailureListener { onFailure() }
                        .addOnCanceledListener { onFailure() }
                        .addOnCompleteListener { imageProxy.close() }
                }

                override fun close() {
                    imageProxy.close()
                }
            })
        }

        cameraProvider.unbindAll()
        cameraProvider.bindToLifecycle(
            lifecycleOwner,
            CameraSelector.DEFAULT_BACK_CAMERA,
            preview,
            imageAnalysis
        )
    }
}
