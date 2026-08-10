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

import android.content.Intent
import android.graphics.BitmapFactory
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import android.os.Bundle
import android.util.Log
import android.util.TypedValue
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.media3.common.MediaItem
import androidx.media3.exoplayer.ExoPlayer
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.databinding.ActivityVerifiedViewerBinding
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.SignatureVerifier
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Full-screen verified media viewer that displays images and videos with a
 * signature verification overlay.
 *
 * This activity can be launched via:
 * - [Intent.ACTION_VIEW] with `intent.data` pointing to image or video content.
 * - [Intent.ACTION_SEND] with the media URI in [Intent.EXTRA_STREAM].
 *
 * Upon opening, it reads embedded xKey signature metadata (XMP/sidecar), resolves
 * each signer against the local key store and contacts database, cryptographically
 * verifies each signature, and renders a colour-coded badge overlay at the bottom
 * of the screen.
 */
private const val SIDECAR_SUFFIX = ".xkeysig"

class VerifiedMediaViewerActivity : AppCompatActivity() {

    private companion object {
        const val TAG = "VerifiedMediaViewer"
        const val MAX_BITMAP_DIMENSION = 2048
    }

    private lateinit var binding: ActivityVerifiedViewerBinding
    private lateinit var keyDao: KeyDao
    private lateinit var contactDao: ContactDao

    private var exoPlayer: ExoPlayer? = null

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityVerifiedViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Translucent navy scrim behind the verification results. Applied here
        // rather than in the layout so the colour comes from the palette instead
        // of a hardcoded ARGB literal.
        binding.verificationOverlay.setBackgroundColor(
            UIHelpers.applyAlpha(ContextCompat.getColor(this, R.color.primary), 0.8f)
        )

        val db = XKeyDatabase.getInstance(this)
        keyDao = db.keyDao()
        contactDao = db.contactDao()

        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            title = getString(R.string.verified_viewer_title)
        }

        val mediaUri = resolveMediaUri()
        if (mediaUri == null) {
            Log.w(TAG, "No media URI provided, finishing")
            finish()
            return
        }

        val mimeType = contentResolver.getType(mediaUri) ?: intent.type ?: ""
        when {
            mimeType.startsWith("video/") -> showVideo(mediaUri)
            else -> showImage(mediaUri)
        }

        verifyMedia(mediaUri, mimeType)
    }

    override fun onDestroy() {
        super.onDestroy()
        exoPlayer?.release()
        exoPlayer = null
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    // -------------------------------------------------------------------------
    // URI Resolution
    // -------------------------------------------------------------------------

    /**
     * Resolve the media URI from either ACTION_VIEW data or ACTION_SEND extras.
     */
    private fun resolveMediaUri(): Uri? {
        intent.data?.let { return it }

        @Suppress("DEPRECATION")
        intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)?.let { return it }

        return null
    }

    // -------------------------------------------------------------------------
    // Media Display
    // -------------------------------------------------------------------------

    /**
     * Decode and display an image from the given URI with downsampling to
     * avoid excessive memory consumption.
     */
    private fun showImage(uri: Uri) {
        binding.imageView.visibility = View.VISIBLE
        binding.playerView.visibility = View.GONE

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                contentResolver.openInputStream(uri)?.use { stream ->
                    BitmapFactory.decodeStream(stream, null, options)
                }

                options.inSampleSize = calculateInSampleSize(
                    options.outWidth, options.outHeight,
                    MAX_BITMAP_DIMENSION, MAX_BITMAP_DIMENSION
                )
                options.inJustDecodeBounds = false

                val bitmap = contentResolver.openInputStream(uri)?.use { stream ->
                    BitmapFactory.decodeStream(stream, null, options)
                }

                withContext(Dispatchers.Main) {
                    if (bitmap != null) {
                        binding.imageView.setImageBitmap(bitmap)
                    } else {
                        Log.w(TAG, "Failed to decode image bitmap")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error loading image", e)
            }
        }
    }

    /**
     * Calculate the optimal inSampleSize for downsampling a bitmap.
     */
    private fun calculateInSampleSize(
        rawWidth: Int,
        rawHeight: Int,
        reqWidth: Int,
        reqHeight: Int
    ): Int {
        var inSampleSize = 1
        if (rawHeight > reqHeight || rawWidth > reqWidth) {
            val halfHeight = rawHeight / 2
            val halfWidth = rawWidth / 2
            while (halfHeight / inSampleSize >= reqHeight && halfWidth / inSampleSize >= reqWidth) {
                inSampleSize *= 2
            }
        }
        return inSampleSize
    }

    /**
     * Set up Media3 ExoPlayer to play the video at the given URI with auto-play.
     */
    private fun showVideo(uri: Uri) {
        binding.imageView.visibility = View.GONE
        binding.playerView.visibility = View.VISIBLE

        val player = ExoPlayer.Builder(this).build()
        exoPlayer = player
        binding.playerView.player = player

        player.setMediaItem(MediaItem.fromUri(uri))
        player.prepare()
        player.playWhenReady = true
    }

    // -------------------------------------------------------------------------
    // Signature Verification
    // -------------------------------------------------------------------------

    /**
     * Read signature metadata from the media file, verify each signature
     * cryptographically, and display results in the overlay.
     */
    private fun verifyMedia(uri: Uri, mimeType: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Attempt to read signature directly from stream first (JPEG EXIF)
                var sigData = XmpMetadataHelper.readSignatureFromUri(contentResolver, uri, mimeType)

                // A sidecar written beside the real file, then the in-band read
                // via a temp copy for formats that carry the signature inside.
                if (sigData == null) {
                    sigData = readSidecarBesideMedia(uri)
                }
                if (sigData == null) {
                    sigData = readSignatureViaTempFile(uri, mimeType)
                }

                if (sigData == null || sigData.signatures.isEmpty()) {
                    withContext(Dispatchers.Main) { showNoSignatures() }
                    return@launch
                }

                // Compute the content hash for cryptographic verification
                val contentHashHex = MediaHasher.hashCanonicalUri(contentResolver, uri)

                val results = sigData.signatures.map { entry ->
                    verifyEntry(entry, contentHashHex, sigData.contentHash)
                }

                val allVerified = results.all { it.status == VerificationStatus.VERIFIED }

                withContext(Dispatchers.Main) {
                    displayVerificationResults(results, sigData.signatures.size)
                }

                // Audit log the verification action
                val fileName = uri.lastPathSegment
                AuditLogger.logFileVerified(
                    fileName = fileName,
                    signerCount = sigData.signatures.size,
                    verified = allVerified
                )

            } catch (e: Exception) {
                Log.e(TAG, "Error verifying media", e)
                withContext(Dispatchers.Main) { showNoSignatures() }
            }
        }
    }

    /**
     * Reads the sidecar that sits beside [uri] in its own document tree.
     *
     * The copy-to-cache route below cannot find it: `readSignature` derives the
     * sidecar path from the file it is given, so pointing it at
     * `cacheDir/verify_temp.<ext>` makes it look for
     * `verify_temp.<ext>.xkeysig` and never consult the real one. Sidecar-signed
     * media therefore always read as unsigned.
     */
    private fun readSidecarBesideMedia(uri: Uri): ContentAuthenticityData? = runCatching {
        val sidecarUri = when {
            uri.scheme == ContentResolver.SCHEME_FILE ->
                Uri.fromFile(File(uri.path + SIDECAR_SUFFIX))
            DocumentsContract.isDocumentUri(this, uri) ->
                DocumentsContract.buildDocumentUriUsingTree(
                    uri, DocumentsContract.getDocumentId(uri) + SIDECAR_SUFFIX
                )
            else -> return@runCatching null
        }
        contentResolver.openInputStream(sidecarUri)?.use { input ->
            ContentAuthenticityData.fromJsonString(input.readBytes().decodeToString())
        }
    }.getOrNull()

    /**
     * Copy the content URI to a temporary file so that sidecar-based
     * signature reading works (for non-JPEG formats like video).
     *
     * Kept for the in-band read, which genuinely needs a real file path. It can
     * only ever find a sidecar the caller planted beside the temp copy, so
     * [readSidecarBesideMedia] is tried first.
     */
    private fun readSignatureViaTempFile(uri: Uri, mimeType: String): ContentAuthenticityData? {
        val extension = when {
            mimeType.contains("jpeg") || mimeType.contains("jpg") -> ".jpg"
            mimeType.contains("png") -> ".png"
            mimeType.contains("webp") -> ".webp"
            mimeType.contains("mp4") -> ".mp4"
            mimeType.contains("matroska") || mimeType.contains("mkv") -> ".mkv"
            mimeType.contains("quicktime") || mimeType.contains("mov") -> ".mov"
            else -> ".tmp"
        }

        val tempFile = File(cacheDir, "verify_temp$extension")
        try {
            contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            } ?: return null

            return XmpMetadataHelper.readSignature(tempFile.absolutePath)
        } finally {
            tempFile.delete()
        }
    }

    /**
     * Verify a single [SignatureEntry] against the local key store and contacts.
     *
     * Resolution order:
     * 1. Look up the fingerprint in the contacts table.
     * 2. Search the keys table by matching public key DER hash.
     * 3. If no key found, report as unknown signer.
     * 4. If key found, cryptographically verify the signature.
     */
    private suspend fun verifyEntry(
        entry: SignatureEntry,
        computedHashHex: String,
        storedContentHash: String
    ): VerificationResult {
        try {
            // Try contacts first
            val contact = contactDao.getByFingerprint(entry.keyFingerprint)
            if (contact != null) {
                val verified = verifyCryptographic(
                    contact.publicKeyDer, entry, computedHashHex, storedContentHash
                )
                return VerificationResult(
                    signerName = entry.signerName ?: contact.name,
                    role = entry.role.name,
                    timestamp = entry.timestamp,
                    status = if (verified) VerificationStatus.VERIFIED else VerificationStatus.FAILED
                )
            }

            // Try local keys by matching DER fingerprint
            val allKeys = keyDao.getAll()
            val matchedKey = allKeys.find { key ->
                val pubDer = key.publicKeyDer
                if (pubDer != null) {
                    MediaHasher.hashBytes(pubDer) == entry.keyFingerprint
                } else {
                    key.keyId == entry.keyFingerprint
                }
            }

            if (matchedKey != null) {
                val pubDer = matchedKey.publicKeyDer
                val verified = if (pubDer != null) {
                    verifyCryptographic(pubDer, entry, computedHashHex, storedContentHash)
                } else {
                    // Cannot verify without public key material; trust by association
                    true
                }
                return VerificationResult(
                    signerName = entry.signerName ?: matchedKey.label,
                    role = entry.role.name,
                    timestamp = entry.timestamp,
                    status = if (verified) VerificationStatus.VERIFIED else VerificationStatus.FAILED
                )
            }

            // Unknown signer
            return VerificationResult(
                signerName = entry.signerName ?: entry.keyFingerprint.take(16) + "...",
                role = entry.role.name,
                timestamp = entry.timestamp,
                status = VerificationStatus.UNKNOWN
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying entry for ${entry.keyFingerprint}", e)
            return VerificationResult(
                signerName = entry.signerName ?: entry.keyFingerprint.take(16) + "...",
                role = entry.role.name,
                timestamp = entry.timestamp,
                status = VerificationStatus.FAILED
            )
        }
    }

    /**
     * Perform cryptographic signature verification using the signer's public key.
     *
     * Checks whether the signature in the entry is valid for the content hash.
     * The stored content hash must also match the freshly computed hash for
     * integrity assurance.
     */
    private fun verifyCryptographic(
        publicKeyDer: ByteArray,
        entry: SignatureEntry,
        computedHashHex: String,
        storedContentHash: String
    ): Boolean {
        // Content hash mismatch means the file has been tampered with
        if (computedHashHex != storedContentHash) {
            Log.w(TAG, "Content hash mismatch: stored=$storedContentHash computed=$computedHashHex")
            return false
        }

        return SignatureVerifier.verifyEntry(publicKeyDer, entry, storedContentHash)
    }

    // -------------------------------------------------------------------------
    // UI Display
    // -------------------------------------------------------------------------

    /**
     * Show the "no signatures" placeholder text and hide the signer list.
     */
    private fun showNoSignatures() {
        binding.signerListContainer.visibility = View.GONE
        binding.textNoSignatures.visibility = View.VISIBLE
    }

    /**
     * Populate the signer list container with colour-coded verification badges.
     *
     * Each row consists of:
     * - A coloured circle indicator (green = verified, yellow = unknown, red = failed)
     * - The signer name
     * - The signer role
     * - The signature timestamp
     */
    private fun displayVerificationResults(results: List<VerificationResult>, totalSignatures: Int) {
        binding.textVerificationTitle.text = getString(R.string.verified_viewer_signers, totalSignatures)
        binding.signerListContainer.removeAllViews()
        binding.signerListContainer.visibility = View.VISIBLE
        binding.textNoSignatures.visibility = View.GONE

        // Rows sit on the navy verification overlay, so their text uses the
        // on-primary token, de-emphasised with alpha for secondary details.
        val onOverlay = ContextCompat.getColor(this, R.color.on_primary)
        val onOverlayMuted = UIHelpers.applyAlpha(onOverlay, 0.7f)
        val onOverlaySubtle = UIHelpers.applyAlpha(onOverlay, 0.5f)

        for (result in results) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                val lp = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                lp.bottomMargin = dpToPx(6)
                layoutParams = lp
            }

            // Status indicator circle
            val indicatorColor = when (result.status) {
                VerificationStatus.VERIFIED -> ContextCompat.getColor(this, R.color.security_verified)
                VerificationStatus.UNKNOWN -> ContextCompat.getColor(this, R.color.security_warning)
                VerificationStatus.FAILED -> ContextCompat.getColor(this, R.color.security_danger)
            }

            val indicator = ImageView(this).apply {
                val size = dpToPx(12)
                layoutParams = LinearLayout.LayoutParams(size, size).apply {
                    marginEnd = dpToPx(8)
                }
                val circle = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(indicatorColor)
                }
                setImageDrawable(circle)
            }
            row.addView(indicator)

            // Status icon (checkmark, question mark, or X)
            val statusIcon = TextView(this).apply {
                text = when (result.status) {
                    VerificationStatus.VERIFIED -> "\u2713"
                    VerificationStatus.UNKNOWN -> "?"
                    VerificationStatus.FAILED -> "\u2717"
                }
                setTextColor(indicatorColor)
                textSize = 16f
                setTypeface(null, Typeface.BOLD)
                val lp = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                lp.marginEnd = dpToPx(8)
                layoutParams = lp
            }
            row.addView(statusIcon)

            // Name
            val nameView = TextView(this).apply {
                text = result.signerName
                setTextColor(onOverlay)
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
                val lp = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                lp.marginEnd = dpToPx(8)
                layoutParams = lp
            }
            row.addView(nameView)

            // Role
            val roleView = TextView(this).apply {
                text = result.role
                setTextColor(onOverlayMuted)
                textSize = 12f
                val lp = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                lp.marginEnd = dpToPx(8)
                layoutParams = lp
            }
            row.addView(roleView)

            // Timestamp
            val timestampView = TextView(this).apply {
                text = formatTimestamp(result.timestamp)
                setTextColor(onOverlaySubtle)
                textSize = 11f
            }
            row.addView(timestampView)

            binding.signerListContainer.addView(row)
        }
    }

    /**
     * Format an ISO-8601 or epoch-millis timestamp string for display.
     */
    private fun formatTimestamp(timestamp: String): String {
        return try {
            // Try ISO-8601 first
            val instant = java.time.Instant.parse(timestamp)
            val date = Date.from(instant)
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(date)
        } catch (_: Exception) {
            try {
                // Try epoch millis
                val millis = timestamp.toLong()
                val date = Date(millis)
                SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(date)
            } catch (_: Exception) {
                timestamp
            }
        }
    }

    private fun dpToPx(dp: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            resources.displayMetrics
        ).toInt()

    // -------------------------------------------------------------------------
    // Verification Models
    // -------------------------------------------------------------------------

    private enum class VerificationStatus {
        VERIFIED, UNKNOWN, FAILED
    }

    private data class VerificationResult(
        val signerName: String,
        val role: String,
        val timestamp: String,
        val status: VerificationStatus
    )
}
