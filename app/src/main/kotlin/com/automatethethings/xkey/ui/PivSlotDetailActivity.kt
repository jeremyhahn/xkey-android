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

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.IBinder
import android.view.Gravity
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.remote.RemotePivCertificate
import com.automatethethings.xkey.remote.RemotePivSignature
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Detail view for a single PIV smart card slot.
 *
 * Displays comprehensive information about a PIV slot including key metadata,
 * public key fingerprint, certificate details (if present), and available actions
 * such as signing test data and key deletion.
 *
 * The slot ID is passed via the [EXTRA_SLOT_ID] intent extra as a hex string
 * (e.g., "9A", "9C").
 *
 * With [EXTRA_DESKTOP] set, the slot is one of the paired desktop's: the
 * certificate comes from `remote.pivGetCert` and the test sign goes through
 * `remote.pivSign`. That view is read-only (no delete, no export).
 *
 * Follows the programmatic UI pattern established by [PasskeyDetailActivity]
 * with section cards, detail rows, and a gradient toolbar.
 */
class PivSlotDetailActivity : AppCompatActivity() {

    companion object {
        /** Intent extra key for the PIV slot hex identifier. */
        const val EXTRA_SLOT_ID = "slot_id"

        /** Intent extra: true when the slot is on the paired desktop. */
        const val EXTRA_DESKTOP = "desktop"

        /** Intent extra: the desktop slot's key algorithm, if the list gave one. */
        const val EXTRA_DESKTOP_ALGORITHM = "desktop_algorithm"

        /** Intent extra: whether the desktop slot holds a key. */
        const val EXTRA_DESKTOP_HAS_KEY = "desktop_has_key"

        /** Number of days before expiry to show warning. */
        private const val EXPIRY_WARNING_DAYS = 30

        /** Milliseconds per day. */
        private const val MS_PER_DAY = 86_400_000L
    }

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private lateinit var pivKeyManager: PivKeyManager
    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private var currentSlotId: String? = null
    private var currentSlot: PivSlot? = null

    /** True when this view shows a paired desktop slot ([EXTRA_DESKTOP]). */
    private var desktopMode = false
    private var gattService: XKeyGattService? = null
    private var serviceBound = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            gattService = (binder as? XKeyGattService.LocalBinder)?.getService()
            currentSlot?.let { loadDesktopSlotDetails(it) }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
        }
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val db = XKeyDatabase.getInstance(this)
        pivKeyManager = PivKeyManager(db.pivSlotDao())

        val slotId = intent.getStringExtra(EXTRA_SLOT_ID) ?: run {
            finish()
            return
        }

        val slot = PivSlot.fromHexId(slotId) ?: run {
            finish()
            return
        }

        currentSlotId = slotId
        currentSlot = slot

        desktopMode = intent.getBooleanExtra(EXTRA_DESKTOP, false)
        buildUI(slot)
        if (desktopMode) {
            showDesktopMessage(getString(R.string.piv_desktop_not_connected))
            // Bind without creating: a desktop is connected only while the
            // service already runs.
            serviceBound = bindService(
                android.content.Intent(this, XKeyGattService::class.java),
                serviceConnection,
                0
            )
        } else {
            loadSlotDetails(slotId)
        }
    }

    override fun onResume() {
        super.onResume()
        if (!desktopMode) currentSlotId?.let { loadSlotDetails(it) }
    }

    override fun onDestroy() {
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        super.onDestroy()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                onBackPressedDispatcher.onBackPressed()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    // -------------------------------------------------------------------------
    // UI Construction
    // -------------------------------------------------------------------------

    private fun buildUI(slot: PivSlot) {
        rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@PivSlotDetailActivity,
                android.R.attr.colorBackground
            ))
        }

        val mainContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }

        buildPremiumToolbar(mainContent, slot)

        val scrollView = NestedScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            clipToPadding = false
            isFillViewport = true
        }

        contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16)
            )
        }

        scrollView.addView(contentLayout)
        mainContent.addView(scrollView)
        rootLayout.addView(mainContent)

        setContentView(rootLayout)
    }

    private fun buildPremiumToolbar(parent: LinearLayout, slot: PivSlot) {
        val toolbarContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val gradient = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(
                ContextCompat.getColor(this, R.color.gradient_tertiary_start),
                ContextCompat.getColor(this, R.color.tertiary_variant)
            )
        )
        toolbarContainer.background = gradient

        val toolbarContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@PivSlotDetailActivity)
            )
            setBackgroundColor(Color.TRANSPARENT)
            title = getString(R.string.piv_detail_title)
            setTitleTextColor(ContextCompat.getColor(this@PivSlotDetailActivity, R.color.on_primary))
            elevation = 0f
        }
        toolbarContent.addView(toolbar)

        // Subtitle with slot badge
        val subtitleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.CENTER_VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16),
                0,
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16)
            )
        }

        // Slot ID badge in toolbar
        val goldColor = ContextCompat.getColor(this, R.color.secondary)
        val slotBadge = TextView(this).apply {
            text = slot.hexId
            textSize = 14f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            setTextColor(ContextCompat.getColor(this@PivSlotDetailActivity, R.color.on_secondary))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 36),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 36)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12)
            }
            background = GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                intArrayOf(goldColor, UIHelpers.applyAlpha(goldColor, 0.8f))
            ).apply {
                cornerRadius = UIHelpers.dpToPx(this@PivSlotDetailActivity, 10f)
            }
        }
        subtitleRow.addView(slotBadge)

        val subtitleText = TextView(this).apply {
            text = getString(R.string.piv_detail_subtitle, slot.hexId, slot.label)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(UIHelpers.applyAlpha(
                ContextCompat.getColor(this@PivSlotDetailActivity, R.color.on_primary),
                0.85f
            ))
        }
        subtitleRow.addView(subtitleText)

        toolbarContent.addView(subtitleRow)
        toolbarContainer.addView(toolbarContent)
        parent.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
        }
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))
    }

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    private fun loadSlotDetails(slotId: String) {
        lifecycleScope.launch {
            val db = XKeyDatabase.getInstance(this@PivSlotDetailActivity)
            val entity = db.pivSlotDao().getBySlotId(slotId) ?: run {
                finish()
                return@launch
            }

            val slot = PivSlot.fromHexId(slotId) ?: run {
                finish()
                return@launch
            }

            contentLayout.removeAllViews()
            displaySlotDetails(slot, entity)
        }
    }

    private fun displaySlotDetails(slot: PivSlot, entity: PivSlotEntity) {
        buildInfoCard(slot, entity)
        buildPublicKeyCard(entity)
        buildCertificateCard(entity.certificateDer) { exportCertificate(entity) }
        buildActionsCard(slot, entity)
    }

    // -------------------------------------------------------------------------
    // Card Builders
    // -------------------------------------------------------------------------

    private fun buildInfoCard(slot: PivSlot, entity: PivSlotEntity) {
        val card = createSectionCard(getString(R.string.piv_section_info))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val dateFormat = SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault())

        addDetailRow(content, getString(R.string.piv_detail_slot_id), slot.hexId)
        addDetailRow(content, getString(R.string.piv_detail_label), slot.label)

        entity.algorithm?.let { algoName ->
            val algorithm = try {
                PivAlgorithm.valueOf(algoName)
            } catch (_: IllegalArgumentException) {
                null
            }
            addDetailRow(content, getString(R.string.piv_detail_algorithm), algorithm?.displayName ?: algoName)
            algorithm?.let {
                addDetailRow(
                    content,
                    getString(R.string.piv_detail_key_size),
                    getString(R.string.piv_detail_key_size_value, it.keySizeBits)
                )
            }
        }

        addDetailRow(content, getString(R.string.piv_detail_created), dateFormat.format(Date(entity.createdAt)))
        addDetailRow(
            content,
            getString(R.string.piv_detail_last_used),
            if (entity.lastUsedAt != null) dateFormat.format(Date(entity.lastUsedAt))
            else getString(R.string.piv_detail_never_used)
        )
        addDetailRow(
            content,
            getString(R.string.piv_detail_use_count),
            getString(R.string.piv_detail_times_used, entity.useCount)
        )

        contentLayout.addView(card)
    }

    private fun buildPublicKeyCard(entity: PivSlotEntity) {
        val card = createSectionCard(getString(R.string.piv_section_public_key))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val publicKeyDer = entity.publicKeyDer
        if (publicKeyDer != null) {
            // SHA-256 fingerprint
            val fingerprint = computeSha256Fingerprint(publicKeyDer)
            addDetailRow(content, getString(R.string.piv_detail_fingerprint), "")

            // Fingerprint in monospace, clickable to copy
            val fingerprintText = TextView(this).apply {
                text = fingerprint
                textSize = 12f
                typeface = Typeface.MONOSPACE
                setTextColor(UIHelpers.resolveThemeColor(
                    this@PivSlotDetailActivity,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12)
                }
                setOnClickListener {
                    copyToClipboard("PIV Public Key Fingerprint", fingerprint)
                    Snackbar.make(
                        rootLayout,
                        R.string.piv_fingerprint_copied,
                        Snackbar.LENGTH_SHORT
                    ).show()
                }
            }
            content.addView(fingerprintText)

            // Export DER button
            val exportButton = MaterialButton(
                this,
                null,
                com.google.android.material.R.attr.materialButtonOutlinedStyle
            ).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                text = getString(R.string.piv_detail_export_pubkey)
                setOnClickListener { exportPublicKey(entity) }
            }
            content.addView(exportButton)
        } else {
            val noKeyText = TextView(this).apply {
                text = getString(R.string.piv_slot_empty)
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
                setTextColor(UIHelpers.resolveThemeColor(
                    this@PivSlotDetailActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
            }
            content.addView(noKeyText)
        }

        contentLayout.addView(card)
    }

    /**
     * The certificate card for [certDer]; the export button shows only with
     * an [onExport] (a desktop slot has none).
     */
    private fun buildCertificateCard(certDer: ByteArray?, onExport: (() -> Unit)?) {
        val card = createSectionCard(getString(R.string.piv_section_certificate))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        if (certDer != null) {
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                val cert = certFactory.generateCertificate(certDer.inputStream()) as X509Certificate

                addDetailRow(content, getString(R.string.piv_cert_subject), extractCn(cert.subjectX500Principal.name))
                addDetailRow(content, getString(R.string.piv_cert_issuer), extractCn(cert.issuerX500Principal.name))
                addDetailRow(content, getString(R.string.piv_cert_serial), cert.serialNumber.toString(16).uppercase())

                val dateFormat = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
                addDetailRow(content, getString(R.string.piv_cert_not_before), dateFormat.format(cert.notBefore))
                addDetailRow(content, getString(R.string.piv_cert_not_after), dateFormat.format(cert.notAfter))

                // Validity status badge
                val now = System.currentTimeMillis()
                val expiryMs = cert.notAfter.time
                val daysUntilExpiry = (expiryMs - now) / MS_PER_DAY

                val (statusText, statusColorRes) = when {
                    daysUntilExpiry < 0 -> getString(R.string.piv_cert_expired) to R.color.security_danger
                    daysUntilExpiry < EXPIRY_WARNING_DAYS ->
                        getString(R.string.piv_cert_expiring) to R.color.security_warning
                    else -> getString(R.string.piv_cert_valid) to R.color.security_verified
                }
                val statusColor = ContextCompat.getColor(this, statusColorRes)

                val statusBadge = TextView(this).apply {
                    text = statusText
                    textSize = 12f
                    setTextColor(ContextCompat.getColor(
                        this@PivSlotDetailActivity,
                        R.color.on_primary
                    ))
                    setPadding(
                        UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12),
                        UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 6),
                        UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12),
                        UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 6)
                    )
                    background = UIHelpers.createRoundedDrawable(
                        statusColor,
                        UIHelpers.dpToPx(this@PivSlotDetailActivity, 12f)
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply {
                        topMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 4)
                        bottomMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12)
                    }
                }
                content.addView(statusBadge)

                // Export certificate button
                if (onExport != null) content.addView(MaterialButton(
                    this,
                    null,
                    com.google.android.material.R.attr.materialButtonOutlinedStyle
                ).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    )
                    text = getString(R.string.piv_cert_export)
                    setOnClickListener { onExport() }
                })
            } catch (_: Exception) {
                val errorText = TextView(this).apply {
                    text = getString(R.string.piv_cert_parse_failed)
                    setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
                    setTextColor(ContextCompat.getColor(
                        this@PivSlotDetailActivity,
                        R.color.security_danger
                    ))
                }
                content.addView(errorText)
            }
        } else {
            val noCertText = TextView(this).apply {
                text = getString(R.string.piv_no_certificate)
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
                setTextColor(UIHelpers.resolveThemeColor(
                    this@PivSlotDetailActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
            }
            content.addView(noCertText)
        }

        contentLayout.addView(card)
    }

    private fun buildActionsCard(slot: PivSlot, entity: PivSlotEntity) {
        val card = createSectionCard(getString(R.string.piv_section_actions))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        // Sign test data button
        val signButton = MaterialButton(
            this,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 8)
            }
            text = getString(R.string.piv_action_sign_test)
            setOnClickListener { signTestData(slot, entity) }
        }
        content.addView(signButton)

        // Delete key button
        val deleteButton = MaterialButton(
            this,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            text = getString(R.string.piv_action_delete)
            setTextColor(getColor(android.R.color.holo_red_dark))
            strokeColor = ColorStateList.valueOf(getColor(android.R.color.holo_red_dark))
            setOnClickListener { showDeleteConfirmation(slot) }
        }
        content.addView(deleteButton)

        contentLayout.addView(card)
    }

    // -------------------------------------------------------------------------
    // UI Helpers
    // -------------------------------------------------------------------------

    private fun createSectionCard(title: String): MaterialCardView {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12)
            }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 20),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 20),
                UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 16)
            )
            tag = "card_content"
        }

        val titleView = TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivSlotDetailActivity,
                androidx.appcompat.R.attr.colorPrimary
            ))
            letterSpacing = 0.02f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 12)
            }
        }
        content.addView(titleView)

        card.addView(content)
        return card
    }

    private fun addDetailRow(parent: LinearLayout, label: String, value: String) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivSlotDetailActivity, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val labelView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivSlotDetailActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }
        row.addView(labelView)

        val valueView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivSlotDetailActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.END
        }
        row.addView(valueView)

        parent.addView(row)
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    private fun signTestData(slot: PivSlot, entity: PivSlotEntity) {
        val algorithm = entity.algorithm?.let { name ->
            try {
                PivAlgorithm.valueOf(name)
            } catch (_: IllegalArgumentException) {
                null
            }
        }

        if (algorithm == null) {
            Snackbar.make(
                rootLayout,
                getString(R.string.piv_sign_test_error, "Unknown algorithm"),
                Snackbar.LENGTH_LONG
            ).show()
            return
        }

        lifecycleScope.launch {
            try {
                val testData = "xKey PIV test signing data".toByteArray()
                val startTime = System.currentTimeMillis()
                withContext(Dispatchers.Default) {
                    pivKeyManager.sign(slot, testData, algorithm)
                }
                val durationMs = System.currentTimeMillis() - startTime
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_sign_test_success, durationMs),
                    Snackbar.LENGTH_SHORT
                ).show()

                // Reload to show updated use count
                currentSlotId?.let { loadSlotDetails(it) }
            } catch (e: Exception) {
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_sign_test_error, e.message),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    // -------------------------------------------------------------------------
    // Paired desktop slot (remote.pivGetCert, remote.pivSign)
    // -------------------------------------------------------------------------

    /** Replaces the content with one line of text (no desktop, or an error). */
    private fun showDesktopMessage(message: String) {
        contentLayout.removeAllViews()
        contentLayout.addView(TextView(this).apply {
            text = message
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivSlotDetailActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        })
    }

    private fun loadDesktopSlotDetails(slot: PivSlot) {
        val client = gattService?.remoteKeyClient() ?: run {
            showDesktopMessage(getString(R.string.piv_desktop_not_connected))
            return
        }
        val actions = DesktopPivSlotActions(client)
        lifecycleScope.launch {
            val cert = try {
                actions.certificate(slot.hexId)
            } catch (e: ProtocolException) {
                showDesktopMessage(getString(R.string.piv_desktop_cert_failed, e.message))
                return@launch
            }
            contentLayout.removeAllViews()
            buildDesktopInfoCard(slot)
            buildCertificateCard(cert?.certificateDer, onExport = null)
            if (intent.getBooleanExtra(EXTRA_DESKTOP_HAS_KEY, false)) {
                buildDesktopActionsCard(slot, actions)
            }
        }
    }

    private fun buildDesktopInfoCard(slot: PivSlot) {
        val card = createSectionCard(getString(R.string.piv_section_info))
        val content = card.findViewWithTag<LinearLayout>("card_content")
        addDetailRow(content, getString(R.string.piv_detail_slot_id), slot.hexId)
        addDetailRow(content, getString(R.string.piv_detail_label), slot.label)
        addDetailRow(content, getString(R.string.piv_detail_location), getString(R.string.piv_location_desktop))
        intent.getStringExtra(EXTRA_DESKTOP_ALGORITHM)?.let {
            addDetailRow(content, getString(R.string.piv_detail_algorithm), it)
        }
        contentLayout.addView(card)
    }

    private fun buildDesktopActionsCard(slot: PivSlot, actions: DesktopPivSlotActions) {
        val card = createSectionCard(getString(R.string.piv_section_actions))
        val content = card.findViewWithTag<LinearLayout>("card_content")
        content.addView(MaterialButton(
            this,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            text = getString(R.string.piv_action_sign_test)
            setOnClickListener { desktopSignTest(slot, actions) }
        })
        contentLayout.addView(card)
    }

    /** The test sign for a desktop slot: one `remote.pivSign` to the desktop. */
    private fun desktopSignTest(slot: PivSlot, actions: DesktopPivSlotActions) {
        lifecycleScope.launch {
            try {
                val startTime = System.currentTimeMillis()
                val result = actions.signTest(slot.hexId)
                val durationMs = System.currentTimeMillis() - startTime
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_desktop_sign_test_success, result.algorithm, durationMs),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: ProtocolException) {
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_sign_test_error, e.message),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun showDeleteConfirmation(slot: PivSlot) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.piv_delete_title)
            .setMessage(getString(R.string.piv_delete_message, slot.hexId, slot.label))
            .setPositiveButton(getString(R.string.piv_action_delete)) { _, _ ->
                deleteKey(slot)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun deleteKey(slot: PivSlot) {
        lifecycleScope.launch {
            try {
                pivKeyManager.deleteKey(slot)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_deleted, slot.hexId),
                    Snackbar.LENGTH_SHORT
                ).show()
                finish()
            } catch (e: Exception) {
                Snackbar.make(
                    rootLayout,
                    "Error: ${e.message}",
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun exportPublicKey(entity: PivSlotEntity) {
        val publicKeyDer = entity.publicKeyDer ?: return
        copyToClipboard("PIV Public Key (DER, hex)", publicKeyDer.toHexString())
        Snackbar.make(
            rootLayout,
            getString(R.string.piv_public_key_der_copied),
            Snackbar.LENGTH_SHORT
        ).show()
    }

    private fun exportCertificate(entity: PivSlotEntity) {
        val certDer = entity.certificateDer ?: return
        copyToClipboard("PIV Certificate (DER, hex)", certDer.toHexString())
        Snackbar.make(
            rootLayout,
            getString(R.string.piv_certificate_der_copied),
            Snackbar.LENGTH_SHORT
        ).show()
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /**
     * Computes the SHA-256 fingerprint of a byte array and returns it as a
     * colon-separated hex string (e.g., "AB:CD:EF:...").
     *
     * @param data The byte array to fingerprint.
     * @return The SHA-256 fingerprint as a colon-separated hex string.
     */
    private fun computeSha256Fingerprint(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return digest.joinToString(":") { "%02X".format(it) }
    }

    /**
     * Extracts the Common Name (CN) from an X.500 distinguished name string.
     *
     * @param dn The distinguished name string (e.g., "CN=example,O=org").
     * @return The CN value, or the full DN if no CN is found.
     */
    private fun extractCn(dn: String): String {
        return dn.split(",")
            .map { it.trim() }
            .firstOrNull { it.startsWith("CN=", ignoreCase = true) }
            ?.substringAfter("=")
            ?: dn
    }

    /**
     * Copies text to the system clipboard.
     *
     * @param label The clip data label.
     * @param text The text to copy.
     */
    private fun copyToClipboard(label: String, text: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
    }

    /**
     * Converts a [ByteArray] to a lowercase hex string.
     *
     * @return The hex string representation.
     */
    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }
}

/**
 * The paired desktop's side of [PivSlotDetailActivity]: the slot certificate
 * from `remote.pivGetCert` and the test sign through `remote.pivSign`.
 */
class DesktopPivSlotActions(private val client: RemoteKeyClient) {

    companion object {
        /** The bytes the "sign test" action asks the desktop to sign. */
        val TEST_DATA: ByteArray = "xKey PIV test signing data".toByteArray()
    }

    /**
     * The slot's certificate, or null when the desktop has none for it
     * ([ErrorCodes.PIV_SLOT_NOT_FOUND]).
     *
     * @throws ProtocolException on any other desktop error or a malformed reply.
     */
    suspend fun certificate(slot: String): RemotePivCertificate? =
        try {
            client.pivGetCert(slot)
        } catch (e: ProtocolException) {
            if (e.errorCode == ErrorCodes.PIV_SLOT_NOT_FOUND) null else throw e
        }

    /** Signs [TEST_DATA] with the slot's key on the desktop. */
    suspend fun signTest(slot: String): RemotePivSignature = client.pivSign(slot, TEST_DATA)
}
