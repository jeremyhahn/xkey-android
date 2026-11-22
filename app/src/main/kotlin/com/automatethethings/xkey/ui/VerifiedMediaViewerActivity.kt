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
import android.net.Uri
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
import com.automatethethings.xkey.media.MediaLocationAccess
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.MediaSaveRuns
import com.automatethethings.xkey.media.SignatureEntry
import com.automatethethings.xkey.media.SignerVerification
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
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
class VerifiedMediaViewerActivity : AppCompatActivity() {

    private companion object {
        const val TAG = "VerifiedMediaViewer"
        const val MAX_BITMAP_DIMENSION = 2048
    }

    private lateinit var binding: ActivityVerifiedViewerBinding

    /** Asks for location access before the media's original is read. */
    private val locationAccess = MediaLocationAccess(this)
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
        // Verification's snapshots a killed process left are reclaimed here.
        MediaSaveRuns.sweepAtScreenStart(lifecycleScope, applicationContext)

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

        // Verifying reads the media whole: a fresh install is asked for location access first.
        locationAccess.withOriginals(listOf(mediaUri)) { verifyMedia(mediaUri, mimeType) }
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
                // The signature embedded in the original and the check of its
                // content hash, both from one read of it: the signature
                // checked is the one in the bytes hashed. Leaving the screen
                // cancels a read the provider stalls.
                val inBand = MediaPublisher.readCancellable { signal ->
                    MediaHasher.checkInBandUri(applicationContext, uri, mimeType, signal)
                }
                var sigData = inBand?.data
                var check = inBand?.check

                // Else the sidecar where the signer wrote it (beside the real
                // file, or the one xKey owns under Documents/xKey/): it may
                // cover the canonical or the whole-file hash.
                if (sigData == null) {
                    sigData = XmpMetadataHelper.readSidecar(applicationContext, uri)
                    if (sigData != null) {
                        val sidecarHash = sigData.contentHash
                        check = MediaPublisher.readCancellable { signal ->
                            MediaHasher.checkContentHashUri(
                                applicationContext, uri, sidecarHash, MediaHasher.SignatureSource.SIDECAR, signal
                            )
                        }
                    }
                }

                if (sigData == null || sigData.signatures.isEmpty() || check == null) {
                    withContext(Dispatchers.Main) { showNoSignatures() }
                    return@launch
                }

                // The stored content hash must match the file before any
                // signature over it is checked.
                if (check == MediaHasher.ContentHashCheck.ACCESS_UNAVAILABLE) {
                    withContext(Dispatchers.Main) { showAccessUnavailable() }
                    return@launch
                }
                val contentHashMatches = check == MediaHasher.ContentHashCheck.MATCHES

                val results = sigData.signatures.map { entry ->
                    verifyEntry(entry, contentHashMatches, sigData.contentHash)
                }

                // Zero signatures verify nothing.
                val allVerified = results.isNotEmpty() && results.all { it.status == VerificationStatus.VERIFIED }

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

            } catch (e: MediaPublisher.OriginalUnavailableException) {
                // Only the redacted view is readable: nothing is verified, and it is no tampering.
                Log.w(TAG, "The original is unreadable without location access", e)
                withContext(Dispatchers.Main) { showAccessUnavailable() }
            } catch (e: Exception) {
                Log.e(TAG, "Error verifying media", e)
                withContext(Dispatchers.Main) { showNoSignatures() }
            }
        }
    }

    /**
     * Verify a single [SignatureEntry] against the local key store and contacts.
     *
     * Looks up the contact and the local keys, then leaves the decision to
     * [SignerVerification.verify], the rule this screen shares with the
     * file-operation screen.
     */
    private suspend fun verifyEntry(
        entry: SignatureEntry,
        contentHashMatches: Boolean,
        storedContentHash: String
    ): VerificationResult {
        val result = try {
            val contact = contactDao.getByFingerprint(entry.keyFingerprint)
            val localKeys = if (contact == null) {
                keyDao.getAll().map {
                    SignerVerification.LocalKey(it.keyId, it.label, it.publicKeyDer)
                }
            } else {
                emptyList()
            }
            SignerVerification.verify(
                entry = entry,
                storedContentHash = storedContentHash,
                contentHashMatches = contentHashMatches,
                contact = contact?.let { SignerVerification.Contact(it.name, it.publicKeyDer) },
                localKeys = localKeys
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying entry for ${entry.keyFingerprint}", e)
            SignerVerification.Result(
                SignerVerification.Status.FAILED,
                entry.signerName ?: (entry.keyFingerprint.take(16) + "...")
            )
        }
        return VerificationResult(
            signerName = result.displayName,
            role = entry.role.name,
            timestamp = entry.timestamp,
            status = when (result.status) {
                SignerVerification.Status.VERIFIED -> VerificationStatus.VERIFIED
                SignerVerification.Status.FAILED -> VerificationStatus.FAILED
                SignerVerification.Status.UNKNOWN -> VerificationStatus.UNKNOWN
            },
            claimedName = result.claimedName
        )
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
     * The original the signatures cover is unreadable (no location access):
     * nothing is verified, and it is not reported as tampering.
     */
    private fun showAccessUnavailable() {
        binding.signerListContainer.visibility = View.GONE
        binding.textNoSignatures.text = MediaHasher.ACCESS_UNAVAILABLE_MESSAGE
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
     *
     * A signer whose file-embedded name differs from the matched name gets a
     * "Claims: <name>" line under its row.
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

            // The name the file embeds is a claim, shown on its own line
            // under the badge row and never as the badge name.
            result.claimedName?.let { claimed ->
                val claimView = TextView(this).apply {
                    text = getString(R.string.verified_viewer_claims, claimed)
                    setTextColor(onOverlayMuted)
                    textSize = 12f
                    setTypeface(null, Typeface.ITALIC)
                    val lp = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    )
                    lp.marginStart = dpToPx(40)
                    lp.bottomMargin = dpToPx(6)
                    layoutParams = lp
                }
                binding.signerListContainer.addView(claimView)
            }
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
        val status: VerificationStatus,
        /** The name the file embeds, when it differs from the matched [signerName]. */
        val claimedName: String? = null
    )
}
