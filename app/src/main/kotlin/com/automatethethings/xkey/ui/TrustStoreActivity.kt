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
import android.content.Context
import android.content.Intent
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.security.KeyChain
import android.text.InputType
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.snackbar.Snackbar
import com.automatethethings.xkey.R
import com.automatethethings.xkey.bootstrap.BootstrapClient
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.settings.BootstrapMethod
import com.automatethethings.xkey.settings.BootstrapSettingsData
import com.automatethethings.xkey.settings.BootstrapSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.CABundleFetchException
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.truststore.TrustedCA
import com.automatethethings.xkey.truststore.clearTrustStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Premium Trust Store management activity for CA certificates.
 *
 * Provides a professional, premium UI for managing trusted CA certificates used
 * to verify IDevID certificate chains from paired devices. Features include:
 *
 * - **Summary Card**: Shows total certificate count with expiration statistics
 * - **Import Options**: Bootstrap from server, import from URL, or import from file
 * - **Certificate List**: Premium cards with expiry indicators and source labels
 * - **Detail Bottom Sheet**: Full certificate details with fingerprint copy support
 *
 * IMPORTANT: Self-signed certificates are never accepted.
 *
 * @see TrustStoreRepository For certificate storage operations
 * @see BootstrapClient For secure CA bundle retrieval
 */
class TrustStoreActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private lateinit var trustStoreRepository: TrustStoreRepository
    private lateinit var bootstrapSettingsRepository: BootstrapSettingsRepository

    // -------------------------------------------------------------------------
    // UI Components
    // -------------------------------------------------------------------------

    private lateinit var rootLayout: LinearLayout
    private lateinit var contentScrollView: NestedScrollView
    private lateinit var contentContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var importOptionsCard: MaterialCardView
    private lateinit var certificateListCard: MaterialCardView
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateView: LinearLayout
    private lateinit var progressIndicator: CircularProgressIndicator

    // Summary card views
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var expiredBadge: TextView
    private lateinit var expiringSoonBadge: TextView
    private lateinit var statsContainer: LinearLayout

    // Import options
    private lateinit var bootstrapProgress: ProgressBar

    private lateinit var adapter: TrustedCertificateAdapter

    // -------------------------------------------------------------------------
    // File Picker
    // -------------------------------------------------------------------------

    /**
     * Activity result launcher for the file picker.
     *
     * Accepts PEM and DER certificate files for import.
     */
    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { importFromUri(it) }
    }

    /**
     * Activity result launcher for system certificate installation.
     *
     * After the system cert install flow completes, refreshes the install status.
     */
    private val systemCertInstallLauncher: ActivityResultLauncher<Intent> =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { _ ->
            lifecycleScope.launch {
                trustStoreRepository.refreshSystemInstallStatus()
                loadCertificates()
            }
        }

    private lateinit var androidCA: AndroidCA

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        /** Days threshold for "expiring soon" warning. */
        private const val EXPIRING_SOON_DAYS = 30

        /** Milliseconds in one day. */
        private const val MILLIS_PER_DAY = 24L * 60L * 60L * 1000L

        /** PEM certificate markers. */
        private const val PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
        private const val PEM_CERT_END = "-----END CERTIFICATE-----"
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        trustStoreRepository = TrustStoreRepository(this)
        bootstrapSettingsRepository = BootstrapSettingsRepository(this)
        androidCA = AndroidCA(this)

        buildUI()
        setContentView(rootLayout)
    }

    override fun onResume() {
        super.onResume()
        loadCertificates()
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

    /**
     * Builds the complete premium UI programmatically.
     */
    private fun buildUI() {
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                android.R.attr.colorBackground
            ))
        }

        buildPremiumToolbar()
        buildProgressIndicator()
        buildScrollableContent()

        rootLayout.addView(progressIndicator)
        rootLayout.addView(contentScrollView)
    }

    /**
     * Creates the premium toolbar with gradient background.
     */
    private fun buildPremiumToolbar() {
        // Toolbar container with gradient
        val toolbarContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Gradient background
        val gradientStart = ContextCompat.getColor(this, R.color.gradient_primary_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_primary_end)
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(gradientStart, gradientEnd)
        )
        toolbarContainer.background = gradient

        // Toolbar
        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@TrustStoreActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.trust_store_title)
            setTitleTextColor(ContextCompat.getColor(this@TrustStoreActivity, R.color.on_primary))
            elevation = 0f
        }

        // Subtitle
        val subtitle = TextView(this).apply {
            text = "Manage trusted CA certificates"
            setTextColor(ContextCompat.getColor(
                this@TrustStoreActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.8f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12)
            )
        }

        toolbarContainer.addView(toolbar)
        toolbarContainer.addView(subtitle)
        rootLayout.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_chevron_right)
        }
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))
    }

    /**
     * Creates the centered progress indicator for loading states.
     */
    private fun buildProgressIndicator() {
        progressIndicator = CircularProgressIndicator(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 24)
            }
            isIndeterminate = true
            visibility = View.GONE
        }
    }

    /**
     * Creates the scrollable content area containing all cards.
     */
    private fun buildScrollableContent() {
        contentScrollView = NestedScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            isFillViewport = true
        }

        contentContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(0, 0, 0, UIHelpers.dpToPxInt(this@TrustStoreActivity, 16))
        }

        buildSummaryCard()
        buildImportOptionsCard()
        buildCertificateListCard()
        buildEmptyState()

        contentContainer.addView(summaryCard)
        contentContainer.addView(importOptionsCard)
        contentContainer.addView(certificateListCard)
        contentContainer.addView(emptyStateView)

        contentScrollView.addView(contentContainer)
    }

    /**
     * Creates the hero summary card showing certificate statistics.
     */
    private fun buildSummaryCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@TrustStoreActivity, 100)
        }

        // Apply gradient background
        val gradientStart = ContextCompat.getColor(this, R.color.gradient_security_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_security_end)
        PremiumCardFactory.applyDiagonalGradient(summaryCard, gradientStart, gradientEnd)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 20),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 20),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 20),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 20)
            )
        }

        // Left section: Count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
        }

        totalCountText = TextView(this).apply {
            text = "0"
            textSize = 48f
            setTextColor(ContextCompat.getColor(this@TrustStoreActivity, R.color.on_primary))
            typeface = android.graphics.Typeface.create("sans-serif-light", android.graphics.Typeface.NORMAL)
        }

        totalLabelText = TextView(this).apply {
            text = resources.getQuantityString(R.plurals.trust_store_total_certificates, 0)
            textSize = 14f
            setTextColor(ContextCompat.getColor(this@TrustStoreActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        countSection.addView(totalCountText)
        countSection.addView(totalLabelText)

        // Right section: Status badges
        statsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.END
        }

        expiredBadge = createStatusBadge(
            "0 expired",
            ContextCompat.getColor(this, R.color.security_danger_container),
            ContextCompat.getColor(this, R.color.on_security_danger_container)
        )

        expiringSoonBadge = createStatusBadge(
            "0 expiring soon",
            ContextCompat.getColor(this, R.color.security_warning_container),
            ContextCompat.getColor(this, R.color.on_security_warning_container)
        )

        statsContainer.addView(expiredBadge)
        statsContainer.addView(expiringSoonBadge)

        cardContent.addView(countSection)
        cardContent.addView(statsContainer)
        summaryCard.addView(cardContent)
    }

    /**
     * Creates a status badge with the specified styling.
     */
    private fun createStatusBadge(text: String, bgColor: Int, textColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 12f
            setTextColor(textColor)
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 6),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 6)
            )
            background = UIHelpers.createRoundedDrawable(
                bgColor,
                UIHelpers.dpToPx(this@TrustStoreActivity, 16f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
            visibility = View.GONE
        }
    }

    /**
     * Creates the import options card with three import methods.
     */
    private fun buildImportOptionsCard() {
        importOptionsCard = PremiumCardFactory.createElevatedCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 8),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
                )
            }
        }
        PremiumCardFactory.setNonInteractive(importOptionsCard)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            )
        }

        // Section header
        val sectionHeader = TextView(this).apply {
            text = "Import Certificates"
            textSize = 16f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            }
        }

        // Bootstrap from server button
        val bootstrapButton = createImportButton(
            icon = R.drawable.ic_bootstrap,
            title = getString(R.string.trust_store_import_bootstrap_title),
            subtitle = getString(R.string.trust_store_import_bootstrap_subtitle)
        ) { showBootstrapDialog() }

        // Progress indicator for bootstrap
        bootstrapProgress = ProgressBar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
            visibility = View.GONE
        }

        // Import from URL button
        val urlButton = createImportButton(
            icon = R.drawable.ic_peer,
            title = getString(R.string.trust_store_import_url_title),
            subtitle = getString(R.string.trust_store_import_url_subtitle)
        ) { showImportFromUrlDialog() }

        // Import from file button
        val fileButton = createImportButton(
            icon = R.drawable.ic_share_key,
            title = getString(R.string.trust_store_import_file_title),
            subtitle = getString(R.string.trust_store_import_file_subtitle)
        ) { openFilePicker() }

        cardContent.addView(sectionHeader)
        cardContent.addView(bootstrapButton)
        cardContent.addView(bootstrapProgress)
        cardContent.addView(urlButton)
        cardContent.addView(fileButton)
        importOptionsCard.addView(cardContent)
    }

    /**
     * Creates an import action button with icon, title, and subtitle.
     */
    private fun createImportButton(
        icon: Int,
        title: String,
        subtitle: String,
        onClick: () -> Unit
    ): MaterialCardView {
        val button = PremiumCardFactory.createOutlinedCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(0, 0, 0, UIHelpers.dpToPxInt(this@TrustStoreActivity, 8))
            }
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12)
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        val iconView = ImageView(this).apply {
            setImageResource(icon)
            imageTintList = ContextCompat.getColorStateList(
                this@TrustStoreActivity,
                R.color.primary
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 32),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 32)
            )
        }

        val textContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            ).apply {
                marginStart = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            }
        }

        val titleText = TextView(this).apply {
            text = title
            textSize = 15f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }

        val subtitleText = TextView(this).apply {
            text = subtitle
            textSize = 13f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }

        val chevron = ImageView(this).apply {
            setImageResource(R.drawable.ic_chevron_right)
            imageTintList = ContextCompat.getColorStateList(
                this@TrustStoreActivity,
                R.color.outline
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24)
            )
        }

        textContainer.addView(titleText)
        textContainer.addView(subtitleText)
        content.addView(iconView)
        content.addView(textContainer)
        content.addView(chevron)
        button.addView(content)

        return button
    }

    /**
     * Creates the certificate list card containing the RecyclerView.
     */
    private fun buildCertificateListCard() {
        certificateListCard = PremiumCardFactory.createElevatedCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 8),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                    UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
                )
            }
        }
        PremiumCardFactory.setNonInteractive(certificateListCard)

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            )
        }

        // Section header with clear all button
        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val sectionHeader = TextView(this).apply {
            text = "Certificates"
            textSize = 16f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
        }

        val clearAllButton = MaterialButton(
            this,
            null,
            androidx.appcompat.R.attr.borderlessButtonStyle
        ).apply {
            text = getString(R.string.trust_store_clear_all)
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                androidx.appcompat.R.attr.colorError
            ))
            setOnClickListener { confirmClearAll() }
        }

        headerRow.addView(sectionHeader)
        headerRow.addView(clearAllButton)

        // RecyclerView
        recyclerView = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@TrustStoreActivity)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            isNestedScrollingEnabled = false
        }

        adapter = TrustedCertificateAdapter(
            onItemClick = { cert -> showCertificateDetailSheet(cert) },
            onDeleteClick = { cert -> confirmDelete(cert) }
        )
        recyclerView.adapter = adapter

        cardContent.addView(headerRow)
        cardContent.addView(recyclerView)
        certificateListCard.addView(cardContent)
    }

    /**
     * Creates the empty state view shown when no certificates are stored.
     */
    private fun buildEmptyState() {
        emptyStateView = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 48)
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 48)
            }
            visibility = View.GONE
        }

        val icon = ImageView(this).apply {
            setImageResource(R.drawable.ic_shield)
            imageTintList = ContextCompat.getColorStateList(
                this@TrustStoreActivity,
                R.color.outline
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 80),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 80)
            )
        }

        val title = TextView(this).apply {
            text = getString(R.string.trust_store_empty)
            textSize = 18f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            }
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.trust_store_empty_hint)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
        }

        val importButton = MaterialButton(this).apply {
            text = "Import your first certificate"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 24)
            }
            setOnClickListener { showImportFromUrlDialog() }
        }

        emptyStateView.addView(icon)
        emptyStateView.addView(title)
        emptyStateView.addView(subtitle)
        emptyStateView.addView(importButton)
    }

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    /**
     * Loads certificates from the repository and updates the UI.
     */
    private fun loadCertificates() {
        lifecycleScope.launch {
            syncAndroidCACertificates()
            val certificates = trustStoreRepository.getAllCertificates()
            updateUI(certificates)
        }
    }

    /**
     * Syncs AndroidCA-generated certificates into the trust store.
     *
     * Imports root and intermediate CA certs (idempotent), then refreshes
     * system install status for badge display.
     */
    private suspend fun syncAndroidCACertificates() {
        try {
            if (androidCA.isRootCAGenerated()) {
                val rootCert = androidCA.getRootCertificate()
                trustStoreRepository.importInternalCACertificate(rootCert, "xKey Root CA")
            }
            if (androidCA.isIntermediateCAGenerated()) {
                val intermediateCert = androidCA.getIntermediateCertificate()
                trustStoreRepository.importInternalCACertificate(intermediateCert, "xKey Intermediate CA")
            }
        } catch (_: Exception) {
            // AndroidCA certs not available yet
        }
        trustStoreRepository.refreshSystemInstallStatus()
    }

    /**
     * Updates all UI components based on the certificate list.
     */
    private fun updateUI(certificates: List<TrustedCA>) {
        val now = System.currentTimeMillis()
        val expiringThreshold = now + (EXPIRING_SOON_DAYS * MILLIS_PER_DAY)

        val expiredCount = certificates.count { it.notAfter < now }
        val expiringSoonCount = certificates.count {
            it.notAfter >= now && it.notAfter <= expiringThreshold
        }

        // Update summary card
        totalCountText.text = certificates.size.toString()
        totalLabelText.text = resources.getQuantityString(
            R.plurals.trust_store_total_certificates,
            certificates.size
        )

        // Update badges
        if (expiredCount > 0) {
            expiredBadge.text = "$expiredCount expired"
            expiredBadge.visibility = View.VISIBLE
        } else {
            expiredBadge.visibility = View.GONE
        }

        if (expiringSoonCount > 0) {
            expiringSoonBadge.text = "$expiringSoonCount expiring soon"
            expiringSoonBadge.visibility = View.VISIBLE
        } else {
            expiringSoonBadge.visibility = View.GONE
        }

        // Update list and empty state
        if (certificates.isEmpty()) {
            certificateListCard.visibility = View.GONE
            emptyStateView.visibility = View.VISIBLE
        } else {
            certificateListCard.visibility = View.VISIBLE
            emptyStateView.visibility = View.GONE
            adapter.submitList(certificates.sortedByDescending { it.importedAt })
        }
    }

    // -------------------------------------------------------------------------
    // Import Actions
    // -------------------------------------------------------------------------

    /**
     * Tally of what one import attempt did with a bundle of certificates.
     *
     * [rejected] is deliberately not folded into [skipped]. A skip means the
     * certificate was already trusted and there is nothing to do; a rejection
     * means the store refused it, and telling the user it was "already imported"
     * hides the one outcome they have to act on.
     */
    private data class ImportOutcome(
        val imported: Int,
        val skipped: Int,
        val rejected: Int,
        val errors: List<String>
    )

    /**
     * Imports each DER-encoded certificate in [certificates] under [label].
     *
     * Both the file picker and the bootstrap dialog import a bundle this way, so
     * the loop and its tally live here rather than being duplicated at each call
     * site and drifting apart.
     */
    private suspend fun importAll(
        certificates: List<ByteArray>,
        label: String
    ): ImportOutcome {
        var imported = 0
        var skipped = 0
        var rejected = 0
        val errors = mutableListOf<String>()

        for (certDER in certificates) {
            try {
                if (trustStoreRepository.importCertificate(certDER, label) != null) {
                    imported++
                } else {
                    skipped++
                }
            } catch (e: IllegalArgumentException) {
                // The store only throws this for a certificate it refuses to
                // trust, which is a failure and not a duplicate.
                rejected++
                errors.add(e.message ?: "Certificate rejected")
            } catch (e: Exception) {
                errors.add(e.message ?: "Unknown error")
            }
        }

        return ImportOutcome(imported, skipped, rejected, errors)
    }

    /**
     * Renders [outcome] as the message shown after an import.
     *
     * Rejections come first: they are the only outcome that needs the user to do
     * something, and reporting them after the "already imported" arm is what let
     * a refused certificate masquerade as a duplicate. [successSuffix] is
     * appended to the plain-success message only, for callers that want to name
     * the transport they used.
     */
    private fun importOutcomeMessage(
        outcome: ImportOutcome,
        successSuffix: String = ""
    ): String = when {
        outcome.rejected > 0 && outcome.imported == 0 ->
            getString(R.string.trust_store_import_rejected, outcome.rejected)
        outcome.rejected > 0 ->
            getString(
                R.string.trust_store_import_partial_rejected,
                outcome.imported,
                outcome.rejected
            )
        outcome.imported > 0 && outcome.errors.isEmpty() ->
            getString(R.string.trust_store_import_success, outcome.imported) + successSuffix
        outcome.imported > 0 ->
            getString(R.string.trust_store_import_partial, outcome.imported, outcome.errors.size)
        outcome.skipped > 0 ->
            getString(R.string.trust_store_import_all_exist)
        else ->
            getString(
                R.string.trust_store_import_failed,
                outcome.errors.firstOrNull() ?: "Unknown"
            )
    }

    /**
     * Shows a dialog to configure and initiate bootstrap from a server.
     *
     * The dialog collects a server URL and bootstrap method selection,
     * then fetches the CA bundle using the chosen method and imports
     * the certificates into the trust store.
     */
    private fun showBootstrapDialog() {
        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                0
            )
        }

        // Server URL input
        val urlLabel = TextView(this).apply {
            text = "Server URL"
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val urlInput = EditText(this).apply {
            hint = "https://kms.example.com:8443"
            setText("https://")
            inputType = InputType.TYPE_TEXT_VARIATION_URI
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // Bootstrap method selection
        val methodLabel = TextView(this).apply {
            text = "Bootstrap Method"
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            }
        }

        val radioGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val daneRadio = RadioButton(this).apply {
            text = BootstrapMethod.DANE.displayName
            id = View.generateViewId()
        }
        val noiseRadio = RadioButton(this).apply {
            text = BootstrapMethod.NOISE.displayName
            id = View.generateViewId()
        }
        val spkiRadio = RadioButton(this).apply {
            text = BootstrapMethod.SPKI.displayName
            id = View.generateViewId()
        }
        val directRadio = RadioButton(this).apply {
            text = BootstrapMethod.DIRECT.displayName
            id = View.generateViewId()
        }

        radioGroup.addView(daneRadio)
        radioGroup.addView(noiseRadio)
        radioGroup.addView(spkiRadio)
        radioGroup.addView(directRadio)

        // Default to DANE
        radioGroup.check(daneRadio.id)

        // Conditional config container for method-specific fields
        val configContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
        }

        // Noise: server static key input
        val noiseKeyInput = EditText(this).apply {
            hint = "Server static key (64 hex chars)"
            inputType = InputType.TYPE_CLASS_TEXT
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        // SPKI: pin SHA-256 input
        val spkiPinInput = EditText(this).apply {
            hint = "SPKI pin SHA-256 (64 hex chars)"
            inputType = InputType.TYPE_CLASS_TEXT
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        configContainer.addView(noiseKeyInput)
        configContainer.addView(spkiPinInput)

        // Show/hide conditional fields based on radio selection
        radioGroup.setOnCheckedChangeListener { _, checkedId ->
            noiseKeyInput.visibility = if (checkedId == noiseRadio.id) View.VISIBLE else View.GONE
            spkiPinInput.visibility = if (checkedId == spkiRadio.id) View.VISIBLE else View.GONE
        }

        dialogLayout.addView(urlLabel)
        dialogLayout.addView(urlInput)
        dialogLayout.addView(methodLabel)
        dialogLayout.addView(radioGroup)
        dialogLayout.addView(configContainer)

        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.trust_store_import_bootstrap_title))
            .setView(dialogLayout)
            .setPositiveButton("Bootstrap") { _, _ ->
                val url = urlInput.text.toString().trim()
                if (url.isBlank() || url == "https://") {
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.trust_store_url_required),
                        Snackbar.LENGTH_SHORT
                    ).show()
                    return@setPositiveButton
                }

                // Determine selected method
                val selectedMethod = when (radioGroup.checkedRadioButtonId) {
                    daneRadio.id -> BootstrapMethod.DANE
                    noiseRadio.id -> BootstrapMethod.NOISE
                    spkiRadio.id -> BootstrapMethod.SPKI
                    directRadio.id -> BootstrapMethod.DIRECT
                    else -> BootstrapMethod.DANE
                }

                // Build settings from dialog inputs
                var settings = BootstrapSettingsData().deriveFromUrl(url)
                settings = when (selectedMethod) {
                    BootstrapMethod.DANE -> settings.copy(
                        daneEnabled = true,
                        noiseEnabled = false,
                        spkiEnabled = false,
                        directEnabled = false
                    )
                    BootstrapMethod.NOISE -> settings.copy(
                        daneEnabled = false,
                        noiseEnabled = true,
                        spkiEnabled = false,
                        directEnabled = false,
                        noiseServerStaticKey = noiseKeyInput.text.toString().trim()
                    )
                    BootstrapMethod.SPKI -> settings.copy(
                        daneEnabled = false,
                        noiseEnabled = false,
                        spkiEnabled = true,
                        directEnabled = false,
                        spkiPinSha256 = spkiPinInput.text.toString().trim()
                    )
                    BootstrapMethod.DIRECT -> settings.copy(
                        daneEnabled = false,
                        noiseEnabled = false,
                        spkiEnabled = false,
                        directEnabled = true
                    )
                }

                bootstrapProgress.visibility = View.VISIBLE

                lifecycleScope.launch {
                    try {
                        val client = BootstrapClient(settings)
                        val result = client.fetchWithMethod(selectedMethod)

                        val outcome = importAll(
                            result.certificates,
                            "Bootstrap (${result.method.displayName})"
                        )

                        bootstrapProgress.visibility = View.GONE

                        val message = importOutcomeMessage(
                            outcome,
                            successSuffix = " via ${result.method.displayName}"
                        )

                        Snackbar.make(rootLayout, message, Snackbar.LENGTH_LONG).show()
                        loadCertificates()

                    } catch (e: Exception) {
                        bootstrapProgress.visibility = View.GONE
                        Snackbar.make(
                            rootLayout,
                            getString(R.string.trust_store_fetch_error, e.message),
                            Snackbar.LENGTH_LONG
                        ).show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Shows the import from URL dialog.
     */
    private fun showImportFromUrlDialog() {
        val inputLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 16),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                0
            )
        }

        val urlInput = EditText(this).apply {
            hint = getString(R.string.trust_store_url_hint)
            setText("https://")
            inputType = InputType.TYPE_TEXT_VARIATION_URI
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val labelInput = EditText(this).apply {
            hint = getString(R.string.trust_store_label_hint)
            inputType = InputType.TYPE_CLASS_TEXT
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
        }

        inputLayout.addView(urlInput)
        inputLayout.addView(labelInput)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.trust_store_import_title)
            .setMessage(R.string.trust_store_import_message)
            .setView(inputLayout)
            .setPositiveButton(R.string.trust_store_import_button) { _, _ ->
                val url = urlInput.text.toString().trim()
                val label = labelInput.text.toString().trim().ifEmpty { null }
                if (url.isNotEmpty() && url != "https://") {
                    importFromUrl(url, label)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Imports CA bundle from the specified URL.
     */
    private fun importFromUrl(url: String, label: String?) {
        progressIndicator.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                val result = trustStoreRepository.importFromURL(url, label)

                progressIndicator.visibility = View.GONE

                // The repository reports its own rejections as plain errors, so
                // there is no separate rejected count to carry here.
                val message = importOutcomeMessage(
                    ImportOutcome(
                        imported = result.imported,
                        skipped = result.skipped,
                        rejected = 0,
                        errors = result.errors
                    )
                )

                Snackbar.make(rootLayout, message, Snackbar.LENGTH_LONG).show()
                loadCertificates()

            } catch (e: CABundleFetchException) {
                progressIndicator.visibility = View.GONE
                Snackbar.make(
                    rootLayout,
                    getString(R.string.trust_store_fetch_error, e.message),
                    Snackbar.LENGTH_LONG
                ).show()
            } catch (e: Exception) {
                progressIndicator.visibility = View.GONE
                Snackbar.make(
                    rootLayout,
                    getString(R.string.trust_store_import_error, e.message),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    /**
     * Opens the Android file picker for certificate files.
     */
    private fun openFilePicker() {
        filePickerLauncher.launch(arrayOf(
            "application/x-pem-file",
            "application/x-x509-ca-cert",
            "application/pkix-cert",
            "*/*"
        ))
    }

    /**
     * Imports certificates from the selected file URI.
     */
    private fun importFromUri(uri: Uri) {
        progressIndicator.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    ?: throw IOException("Failed to read file")

                val fileName = getFileName(uri)
                val certificates = parseCertificatesFromBytes(bytes)

                if (certificates.isEmpty()) {
                    progressIndicator.visibility = View.GONE
                    Snackbar.make(
                        rootLayout,
                        getString(R.string.trust_store_no_certificates_in_file),
                        Snackbar.LENGTH_LONG
                    ).show()
                    return@launch
                }

                val outcome = importAll(
                    certificates.map { it.encoded },
                    fileName ?: "File import"
                )

                progressIndicator.visibility = View.GONE

                val message = importOutcomeMessage(outcome)

                Snackbar.make(rootLayout, message, Snackbar.LENGTH_LONG).show()
                loadCertificates()

            } catch (e: Exception) {
                progressIndicator.visibility = View.GONE
                Snackbar.make(
                    rootLayout,
                    getString(R.string.trust_store_import_error, e.message),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    /**
     * Extracts the file name from a content URI.
     */
    private fun getFileName(uri: Uri): String? {
        var result: String? = null
        if (uri.scheme == "content") {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) {
                        result = cursor.getString(index)
                    }
                }
            }
        }
        if (result == null) {
            result = uri.path?.substringAfterLast('/')
        }
        return result
    }

    /**
     * Parses X509 certificates from raw bytes (PEM or DER format).
     */
    private fun parseCertificatesFromBytes(bytes: ByteArray): List<X509Certificate> {
        val certFactory = CertificateFactory.getInstance("X.509")
        val certificates = mutableListOf<X509Certificate>()

        // Try PEM format first
        val pemString = String(bytes, Charsets.UTF_8)
        if (pemString.contains(PEM_CERT_BEGIN)) {
            var startIndex = 0
            while (true) {
                val beginIndex = pemString.indexOf(PEM_CERT_BEGIN, startIndex)
                if (beginIndex == -1) break

                val endIndex = pemString.indexOf(PEM_CERT_END, beginIndex)
                if (endIndex == -1) break

                val certPem = pemString.substring(beginIndex, endIndex + PEM_CERT_END.length)
                try {
                    val cert = certFactory.generateCertificate(
                        ByteArrayInputStream(certPem.toByteArray(Charsets.UTF_8))
                    ) as X509Certificate
                    certificates.add(cert)
                } catch (e: Exception) {
                    // Skip malformed certificate
                }

                startIndex = endIndex + PEM_CERT_END.length
            }
            return certificates
        }

        // Try DER format
        try {
            val cert = certFactory.generateCertificate(
                ByteArrayInputStream(bytes)
            ) as X509Certificate
            certificates.add(cert)
        } catch (e: Exception) {
            // Not a valid certificate
        }

        return certificates
    }

    // -------------------------------------------------------------------------
    // Certificate Detail Bottom Sheet
    // -------------------------------------------------------------------------

    /**
     * Shows the certificate detail bottom sheet.
     */
    private fun showCertificateDetailSheet(cert: TrustedCA) {
        val bottomSheet = BottomSheetDialog(this)
        val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
        val now = System.currentTimeMillis()
        val isExpired = cert.notAfter < now
        val isExpiringSoon = !isExpired && cert.notAfter <= now + (EXPIRING_SOON_DAYS * MILLIS_PER_DAY)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 24)
            )
        }

        // Header
        val header = TextView(this).apply {
            text = getString(R.string.trust_store_detail_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            }
        }

        // Status indicator
        val statusColor = when {
            isExpired -> ContextCompat.getColor(this, R.color.security_danger)
            isExpiringSoon -> ContextCompat.getColor(this, R.color.security_warning)
            else -> ContextCompat.getColor(this, R.color.security_verified)
        }

        val statusText = when {
            isExpired -> getString(R.string.trust_store_status_expired)
            isExpiringSoon -> getString(R.string.trust_store_status_expiring)
            else -> getString(R.string.trust_store_status_valid)
        }

        val statusBadge = TextView(this).apply {
            text = statusText
            textSize = 12f
            setTextColor(ContextCompat.getColor(this@TrustStoreActivity, android.R.color.white))
            setPadding(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 4),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 12),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                statusColor,
                UIHelpers.dpToPx(this@TrustStoreActivity, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
            }
        }

        // Detail fields
        val subjectField = createDetailField(
            getString(R.string.trust_store_detail_subject),
            cert.subjectDN
        )

        val issuerField = createDetailField(
            getString(R.string.trust_store_detail_issuer),
            cert.issuerDN
        )

        val validFromField = createDetailField(
            getString(R.string.trust_store_detail_valid_from),
            dateFormat.format(Date(cert.notBefore))
        )

        val validUntilField = createDetailField(
            getString(R.string.trust_store_detail_valid_until),
            dateFormat.format(Date(cert.notAfter)),
            statusColor.takeIf { isExpired || isExpiringSoon }
        )

        // Fingerprint with copy button
        val fingerprintContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 12)
            }
        }

        val fingerprintLabel = TextView(this).apply {
            text = getString(R.string.trust_store_detail_fingerprint)
            textSize = 12f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }

        val fingerprintRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val fingerprintValue = TextView(this).apply {
            text = cert.fingerprint.chunked(8).joinToString(" ")
            textSize = 13f
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = android.graphics.Typeface.MONOSPACE
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
        }

        val copyButton = ImageButton(this).apply {
            setImageResource(android.R.drawable.ic_menu_share)
            imageTintList = ContextCompat.getColorStateList(
                this@TrustStoreActivity,
                R.color.primary
            )
            background = null
            contentDescription = getString(R.string.trust_store_copy_fingerprint)
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 40),
                UIHelpers.dpToPxInt(this@TrustStoreActivity, 40)
            )
            setOnClickListener {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Fingerprint", cert.fingerprint))
                Snackbar.make(content, "Fingerprint copied", Snackbar.LENGTH_SHORT).show()
            }
        }

        fingerprintRow.addView(fingerprintValue)
        fingerprintRow.addView(copyButton)
        fingerprintContainer.addView(fingerprintLabel)
        fingerprintContainer.addView(fingerprintRow)

        // Source and label
        val sourceField = createDetailField(
            getString(R.string.trust_store_detail_source),
            cert.source
        )

        val labelField = if (cert.label != null) {
            createDetailField(getString(R.string.trust_store_detail_label), cert.label)
        } else null

        // Install to system button
        val installButton = if (cert.systemInstalled) {
            TextView(this).apply {
                text = getString(R.string.cert_already_system)
                textSize = 14f
                setTextColor(ContextCompat.getColor(this@TrustStoreActivity, R.color.security_verified))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
                }
                gravity = Gravity.CENTER
            }
        } else {
            MaterialButton(this).apply {
                text = getString(R.string.install_to_system)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 16)
                }
                setOnClickListener {
                    bottomSheet.dismiss()
                    installCertificateToSystem(cert)
                }
            }
        }

        // Delete button
        val deleteButton = MaterialButton(
            this,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            text = getString(R.string.trust_store_delete)
            setTextColor(UIHelpers.resolveThemeColor(
                this@TrustStoreActivity,
                androidx.appcompat.R.attr.colorError
            ))
            strokeColor = ContextCompat.getColorStateList(
                this@TrustStoreActivity,
                R.color.error
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 8)
            }
            setOnClickListener {
                bottomSheet.dismiss()
                confirmDelete(cert)
            }
        }

        content.addView(header)
        content.addView(statusBadge)
        content.addView(subjectField)
        content.addView(issuerField)
        content.addView(validFromField)
        content.addView(validUntilField)
        content.addView(fingerprintContainer)
        content.addView(sourceField)
        labelField?.let { content.addView(it) }
        content.addView(installButton)
        content.addView(deleteButton)

        bottomSheet.setContentView(content)
        bottomSheet.show()
    }

    /**
     * Creates a detail field with label and value.
     */
    private fun createDetailField(label: String, value: String, valueColor: Int? = null): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@TrustStoreActivity, 12)
            }

            val labelView = TextView(this@TrustStoreActivity).apply {
                text = label
                textSize = 12f
                setTextColor(UIHelpers.resolveThemeColor(
                    this@TrustStoreActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
            }

            val valueView = TextView(this@TrustStoreActivity).apply {
                text = value
                textSize = 14f
                setTextColor(valueColor ?: UIHelpers.resolveThemeColor(
                    this@TrustStoreActivity,
                    com.google.android.material.R.attr.colorOnSurface
                ))
            }

            addView(labelView)
            addView(valueView)
        }
    }

    // -------------------------------------------------------------------------
    // Confirmations
    // -------------------------------------------------------------------------

    /**
     * Confirms and deletes a certificate.
     */
    private fun confirmDelete(cert: TrustedCA) {
        val displayName = extractCN(cert.subjectDN) ?: cert.subjectDN.take(40)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.trust_store_delete_title)
            .setMessage(getString(R.string.trust_store_delete_message, displayName))
            .setPositiveButton(R.string.trust_store_delete) { _, _ ->
                lifecycleScope.launch {
                    deleteFromTrustStoreScreen(
                        trustStoreRepository,
                        cert.fingerprint,
                        deleteRow = {
                            XKeyDatabase.getInstance(this@TrustStoreActivity)
                                .certificateDao()
                                .deleteByFingerprint(cert.fingerprint)
                        },
                        showResult = { removed ->
                            if (removed) {
                                Snackbar.make(rootLayout, R.string.trust_store_deleted, Snackbar.LENGTH_SHORT)
                                    .show()
                            } else {
                                Snackbar.make(
                                    rootLayout,
                                    "Certificate could not be removed; it is still trusted",
                                    Snackbar.LENGTH_LONG
                                ).show()
                            }
                        },
                        refresh = { loadCertificates() }
                    )
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Confirms and clears all certificates.
     */
    private fun confirmClearAll() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.trust_store_clear_title)
            .setMessage(R.string.trust_store_clear_message)
            .setPositiveButton(R.string.trust_store_clear_all) { _, _ ->
                lifecycleScope.launch {
                    val certDao = XKeyDatabase.getInstance(this@TrustStoreActivity).certificateDao()
                    // Rows go only for the certificates the trust store removed.
                    val result = clearTrustStore(trustStoreRepository) { certDao.deleteByFingerprint(it) }
                    if (result.complete) {
                        Snackbar.make(
                            rootLayout,
                            R.string.trust_store_cleared,
                            Snackbar.LENGTH_SHORT
                        ).show()
                    } else {
                        Snackbar.make(
                            rootLayout,
                            "Trust store only partly cleared: ${result.failed.size} " +
                                "certificate(s) could not be removed and are still trusted",
                            Snackbar.LENGTH_LONG
                        ).show()
                    }
                    loadCertificates()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Launches the Android system certificate installer for the given certificate.
     */
    private fun installCertificateToSystem(cert: TrustedCA) {
        lifecycleScope.launch {
            val certDER = trustStoreRepository.getCertificateDER(cert.fingerprint)
            if (certDER == null) {
                Snackbar.make(
                    rootLayout,
                    getString(R.string.cert_install_failed),
                    Snackbar.LENGTH_SHORT
                ).show()
                return@launch
            }

            val installIntent = KeyChain.createInstallIntent()
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, certDER)
            cert.label?.let { installIntent.putExtra(KeyChain.EXTRA_NAME, it) }
            systemCertInstallLauncher.launch(installIntent)
        }
    }

    /**
     * Extracts the Common Name (CN) from a Distinguished Name string.
     */
    private fun extractCN(dn: String): String? {
        val regex = "CN=([^,]+)".toRegex(RegexOption.IGNORE_CASE)
        return regex.find(dn)?.groupValues?.getOrNull(1)?.trim()
    }
}

// =============================================================================
// RecyclerView Adapter
// =============================================================================

/**
 * Adapter for displaying trusted CA certificates with premium styling.
 */
private class TrustedCertificateAdapter(
    private val onItemClick: (TrustedCA) -> Unit,
    private val onDeleteClick: (TrustedCA) -> Unit
) : ListAdapter<TrustedCA, TrustedCertificateAdapter.ViewHolder>(DiffCallback) {

    companion object {
        private const val EXPIRING_SOON_DAYS = 30
        private const val MILLIS_PER_DAY = 24L * 60L * 60L * 1000L
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val card = PremiumCardFactory.createCompactCard(parent.context).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(0, UIHelpers.dpToPxInt(parent.context, 4), 0, UIHelpers.dpToPxInt(parent.context, 4))
            }
        }
        return ViewHolder(card)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position), onItemClick, onDeleteClick)
    }

    class ViewHolder(private val card: MaterialCardView) : RecyclerView.ViewHolder(card) {
        private val dateFormat = SimpleDateFormat("MMM dd, yyyy", Locale.getDefault())

        fun bind(
            cert: TrustedCA,
            onItemClick: (TrustedCA) -> Unit,
            onDeleteClick: (TrustedCA) -> Unit
        ) {
            val context = card.context
            card.removeAllViews()

            val now = System.currentTimeMillis()
            val isExpired = cert.notAfter < now
            val isExpiringSoon = !isExpired && cert.notAfter <= now + (EXPIRING_SOON_DAYS * MILLIS_PER_DAY)

            val content = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                setPadding(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 12)
                )
                gravity = Gravity.CENTER_VERTICAL
            }

            // Status icon
            val iconColor = when {
                isExpired -> ContextCompat.getColor(context, R.color.security_danger)
                isExpiringSoon -> ContextCompat.getColor(context, R.color.security_warning)
                else -> ContextCompat.getColor(context, R.color.security_verified)
            }

            val icon = ImageView(context).apply {
                setImageResource(
                    if (isExpired) R.drawable.ic_warning else R.drawable.ic_shield_check
                )
                imageTintList = android.content.res.ColorStateList.valueOf(iconColor)
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 40),
                    UIHelpers.dpToPxInt(context, 40)
                )
            }

            // Text content
            val textContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f
                ).apply {
                    marginStart = UIHelpers.dpToPxInt(context, 12)
                }
            }

            // Extract CN or use label
            val displayName = extractCN(cert.subjectDN) ?: cert.label ?: cert.subjectDN.take(40)

            val titleText = TextView(context).apply {
                text = displayName
                textSize = 15f
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
            }

            val expiryText = TextView(context).apply {
                text = if (isExpired) {
                    context.getString(R.string.trust_store_item_expired, dateFormat.format(Date(cert.notAfter)))
                } else {
                    context.getString(R.string.trust_store_item_expires, dateFormat.format(Date(cert.notAfter)))
                }
                textSize = 13f
                setTextColor(when {
                    isExpired -> ContextCompat.getColor(context, R.color.security_danger)
                    isExpiringSoon -> ContextCompat.getColor(context, R.color.security_warning)
                    else -> UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorOnSurfaceVariant)
                })
            }

            // Badge row
            val badgeRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 4)
                }
            }

            // Source badge
            val sourceBadge = TextView(context).apply {
                text = when {
                    cert.source == "internal-ca" -> context.getString(R.string.source_internal_ca)
                    cert.source.startsWith("Bootstrap") -> "Bootstrap"
                    cert.source.startsWith("url:") -> "URL"
                    cert.source == "manual" -> "Manual"
                    else -> "File"
                }
                textSize = 11f
                val badgeBg = if (cert.source == "internal-ca") {
                    UIHelpers.resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary)
                } else {
                    ContextCompat.getColor(context, R.color.primary_container)
                }
                val badgeFg = if (cert.source == "internal-ca") {
                    ContextCompat.getColor(context, R.color.on_primary)
                } else {
                    ContextCompat.getColor(context, R.color.on_primary_container)
                }
                setTextColor(badgeFg)
                setPadding(
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 2),
                    UIHelpers.dpToPxInt(context, 8),
                    UIHelpers.dpToPxInt(context, 2)
                )
                background = UIHelpers.createRoundedDrawable(badgeBg, UIHelpers.dpToPx(context, 8f))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            }
            badgeRow.addView(sourceBadge)

            // System badge (green, with shield indicator)
            if (cert.systemInstalled) {
                val systemBadge = TextView(context).apply {
                    text = context.getString(R.string.cert_system_installed)
                    textSize = 11f
                    setTextColor(ContextCompat.getColor(context, android.R.color.white))
                    setPadding(
                        UIHelpers.dpToPxInt(context, 8),
                        UIHelpers.dpToPxInt(context, 2),
                        UIHelpers.dpToPxInt(context, 8),
                        UIHelpers.dpToPxInt(context, 2)
                    )
                    background = UIHelpers.createRoundedDrawable(
                        ContextCompat.getColor(context, R.color.security_verified),
                        UIHelpers.dpToPx(context, 8f)
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply {
                        marginStart = UIHelpers.dpToPxInt(context, 4)
                    }
                }
                badgeRow.addView(systemBadge)
            }

            textContainer.addView(titleText)
            textContainer.addView(expiryText)
            textContainer.addView(badgeRow)

            // Delete button
            val deleteButton = ImageButton(context).apply {
                setImageResource(R.drawable.ic_delete)
                imageTintList = ContextCompat.getColorStateList(context, R.color.error)
                background = null
                contentDescription = context.getString(R.string.trust_store_delete)
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 44),
                    UIHelpers.dpToPxInt(context, 44)
                )
                setOnClickListener { onDeleteClick(cert) }
            }

            content.addView(icon)
            content.addView(textContainer)
            content.addView(deleteButton)

            card.addView(content)
            card.setOnClickListener { onItemClick(cert) }
            card.setOnLongClickListener {
                onDeleteClick(cert)
                true
            }
        }

        private fun extractCN(dn: String): String? {
            val regex = "CN=([^,]+)".toRegex(RegexOption.IGNORE_CASE)
            return regex.find(dn)?.groupValues?.getOrNull(1)?.trim()
        }
    }

    private object DiffCallback : DiffUtil.ItemCallback<TrustedCA>() {
        override fun areItemsTheSame(oldItem: TrustedCA, newItem: TrustedCA): Boolean {
            return oldItem.fingerprint == newItem.fingerprint
        }

        override fun areContentsTheSame(oldItem: TrustedCA, newItem: TrustedCA): Boolean {
            return oldItem == newItem
        }
    }
}

/**
 * Deletes one certificate for the trust-store screen's confirmation.
 *
 * @param deleteRow deletes the certificate's database row
 * @param showResult shows whether the certificate was removed
 * @param refresh reloads the displayed list
 */
internal suspend fun deleteFromTrustStoreScreen(
    repository: TrustStoreRepository,
    fingerprint: String,
    deleteRow: suspend () -> Unit,
    showResult: (removed: Boolean) -> Unit,
    refresh: () -> Unit
) {
    if (repository.deleteCertificate(fingerprint)) {
        deleteRow()
        showResult(true)
        refresh()
    }
}
