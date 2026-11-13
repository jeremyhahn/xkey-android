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

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CertificateEntity
import com.automatethethings.xkey.ca.CertificateProfile
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.x500.X500Name
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Activity for managing X.509 certificates issued by the local CA.
 *
 * Provides a professional Material 3 UI for certificate lifecycle management including
 * viewing, filtering, exporting, revoking, and deleting certificates. Certificates are
 * observed reactively via Room Flow queries for real-time UI updates.
 *
 * Features:
 * - Hero summary card with certificate statistics and colored status badges
 * - Pill-shaped filter chips for profile and status filtering
 * - RecyclerView with DiffUtil for efficient list updates
 * - Long-press context menu for certificate operations
 * - FAB for future certificate issuance
 */
class CertificateManagementActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        /** Menu item ID for viewing certificate details. */
        private const val MENU_VIEW_DETAILS = 1
        /** Menu item ID for exporting certificate PEM. */
        private const val MENU_EXPORT_PEM = 2
        /** Menu item ID for revoking a certificate. */
        private const val MENU_REVOKE = 3
        /** Menu item ID for deleting a certificate record. */
        private const val MENU_DELETE = 4

        /** Animation duration for chip selection. */
        private const val CHIP_ANIMATION_DURATION = 200L
        /** Animation duration for FAB show/hide. */
        private const val FAB_ANIMATION_DURATION = 250L

        /** Threshold for "expiring soon" in milliseconds (30 days). */
        private const val EXPIRING_SOON_THRESHOLD_MS = 30L * 24 * 60 * 60 * 1000

        /** Regex for extracting CN from a distinguished name. */
        private val CN_REGEX = Regex("CN=([^,]+)")
    }

    // -------------------------------------------------------------------------
    // Filter Constants
    // -------------------------------------------------------------------------

    /** Filter value representing "all certificates" (no filter applied). */
    private val FILTER_ALL: String? = null
    private val FILTER_TLS_SERVER = "tls-server"
    private val FILTER_TLS_CLIENT = "tls-client"
    private val FILTER_IDEVID = "idevid"
    private val FILTER_CODE_SIGNING = "code-signing"
    private val FILTER_EMAIL = "email"
    private val FILTER_OCSP = "ocsp-responder"
    private val FILTER_TIMESTAMPING = "timestamping"
    private val FILTER_CA = "subordinate-ca"
    private val FILTER_REVOKED = "__revoked__"
    private val FILTER_EXPIRED = "__expired__"

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private val certificateDao by lazy { XKeyDatabase.getInstance(this).certificateDao() }
    private val androidCA by lazy { AndroidCA(this) }
    private val keystoreManager by lazy { KeystoreManager(this) }
    private val keyDao by lazy { XKeyDatabase.getInstance(this).keyDao() }
    private val keyPolicyStore by lazy { KeyPolicyStore.of(XKeyDatabase.getInstance(this)) }

    // -------------------------------------------------------------------------
    // UI Components
    // -------------------------------------------------------------------------

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var filterScrollView: HorizontalScrollView
    private lateinit var chipContainer: LinearLayout
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var fab: ExtendedFloatingActionButton
    private lateinit var adapter: CertificateListAdapter

    // Summary card views
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var badgeContainer: LinearLayout

    // Filter chip tracking
    private val filterChips = mutableMapOf<String?, View>()
    private var currentFilter: String? = null
    private var allCertificates: List<CertificateEntity> = emptyList()

    // FAB visibility tracking
    private var isFabVisible = true

    // Date formatter
    private val dateFormat = SimpleDateFormat("MMM dd, yyyy", Locale.getDefault())

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUI()
        setContentView(rootLayout)
        androidCA.certificateDao = certificateDao
        observeCertificates()
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
     * Builds the complete UI programmatically.
     */
    private fun buildUI() {
        rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@CertificateManagementActivity,
                android.R.attr.colorBackground
            ))
        }

        contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        buildToolbar()
        buildSummaryHeroCard()
        buildFilterBar()
        buildCertificateList()
        buildEmptyState()
        buildFab()

        rootLayout.addView(contentLayout)
        rootLayout.addView(fab)
    }

    /**
     * Creates the toolbar with gradient background and back navigation.
     */
    private fun buildToolbar() {
        val toolbarContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val gradientStart = ContextCompat.getColor(this, R.color.gradient_primary_start)
        val gradientEnd = ContextCompat.getColor(this, R.color.gradient_primary_end)
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(gradientStart, gradientEnd)
        )
        toolbarContainer.background = gradient

        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@CertificateManagementActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.certificate_management_title)
            setTitleTextColor(ContextCompat.getColor(
                this@CertificateManagementActivity,
                R.color.on_primary
            ))
            elevation = 0f
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.certificate_management_subtitle)
            setTextColor(ContextCompat.getColor(
                this@CertificateManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12)
            )
        }

        toolbarContainer.addView(toolbar)
        toolbarContainer.addView(subtitle)
        contentLayout.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            setHomeAsUpIndicator(R.drawable.ic_chevron_right)
        }
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))
    }

    /**
     * Creates the hero summary card with certificate statistics and status badges.
     */
    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 100)
        }

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
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 20),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 20),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 20),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 20)
            )
        }

        // Left section: Certificate icon and count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        val certIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_certificate)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@CertificateManagementActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 64),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16)
            }
        }

        val textSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        totalCountText = TextView(this).apply {
            text = "0"
            textSize = 48f
            setTextColor(ContextCompat.getColor(
                this@CertificateManagementActivity,
                R.color.on_primary
            ))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.cert_summary_total)
            textSize = 14f
            setTextColor(ContextCompat.getColor(
                this@CertificateManagementActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        countSection.addView(certIcon)
        countSection.addView(textSection)

        // Right section: Status breakdown badges
        badgeContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.END
        }

        cardContent.addView(countSection)
        cardContent.addView(badgeContainer)
        summaryCard.addView(cardContent)
        contentLayout.addView(summaryCard)
    }

    /**
     * Creates a summary badge for the hero card.
     */
    private fun createSummaryBadge(text: String, bgColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(ContextCompat.getColor(
                this@CertificateManagementActivity,
                R.color.on_primary
            ))
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 10),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 4),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 10),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(bgColor, 0.3f),
                UIHelpers.dpToPx(this@CertificateManagementActivity, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 4)
            }
        }
    }

    /**
     * Creates the horizontal scrollable filter chip bar.
     */
    private fun buildFilterBar() {
        filterScrollView = HorizontalScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            isHorizontalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }

        filterScrollView.isHorizontalFadingEdgeEnabled = true
        filterScrollView.setFadingEdgeLength(UIHelpers.dpToPxInt(this, 32))

        chipContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 8),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 8)
            )
        }

        val filterTypes = listOf(
            FILTER_ALL to getString(R.string.cert_filter_all),
            FILTER_TLS_SERVER to getString(R.string.cert_filter_tls_server),
            FILTER_TLS_CLIENT to getString(R.string.cert_filter_tls_client),
            FILTER_IDEVID to getString(R.string.cert_filter_idevid),
            FILTER_CODE_SIGNING to getString(R.string.cert_filter_code_signing),
            FILTER_EMAIL to getString(R.string.cert_filter_email),
            FILTER_OCSP to getString(R.string.cert_filter_ocsp),
            FILTER_TIMESTAMPING to getString(R.string.cert_filter_timestamping),
            FILTER_CA to getString(R.string.cert_filter_ca),
            FILTER_REVOKED to getString(R.string.cert_filter_revoked),
            FILTER_EXPIRED to getString(R.string.cert_filter_expired)
        )

        filterTypes.forEachIndexed { index, (type, label) ->
            val chip = createFilterChip(label, index == 0)
            chip.setOnClickListener {
                selectFilterChip(type)
            }
            filterChips[type] = chip
            chipContainer.addView(chip)
        }

        filterScrollView.addView(chipContainer)
        contentLayout.addView(filterScrollView)
    }

    /**
     * Creates a pill-shaped filter chip.
     */
    private fun createFilterChip(text: String, isSelected: Boolean): View {
        val chip = TextView(this).apply {
            this.text = text
            textSize = 14f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 20),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 10),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 20),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 10)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 8)
            }
        }

        updateChipStyle(chip, isSelected)
        return chip
    }

    /**
     * Updates chip visual style based on selection state.
     */
    private fun updateChipStyle(chip: View, isSelected: Boolean) {
        val textView = chip as TextView

        if (isSelected) {
            val selectedColor = ContextCompat.getColor(this, R.color.secondary)
            val textColor = ContextCompat.getColor(this, R.color.on_secondary)

            textView.setTextColor(textColor)
            textView.background = UIHelpers.createPillDrawable(
                selectedColor,
                UIHelpers.dpToPx(this, 40f)
            )
        } else {
            val outlineColor = UIHelpers.resolveThemeColor(
                this,
                com.google.android.material.R.attr.colorOutlineVariant
            )
            val textColor = UIHelpers.resolveThemeColor(
                this,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            )

            textView.setTextColor(textColor)
            textView.background = UIHelpers.createRoundedDrawable(
                android.graphics.Color.TRANSPARENT,
                UIHelpers.dpToPx(this, 20f),
                UIHelpers.dpToPxInt(this, 1),
                outlineColor
            )
        }
    }

    /**
     * Selects a filter chip with animation.
     */
    private fun selectFilterChip(type: String?) {
        filterChips[currentFilter]?.let { previousChip ->
            updateChipStyle(previousChip, false)
        }

        filterChips[type]?.let { newChip ->
            val scaleX = ObjectAnimator.ofFloat(newChip, View.SCALE_X, 0.95f, 1f)
            val scaleY = ObjectAnimator.ofFloat(newChip, View.SCALE_Y, 0.95f, 1f)
            AnimatorSet().apply {
                playTogether(scaleX, scaleY)
                duration = CHIP_ANIMATION_DURATION
                interpolator = DecelerateInterpolator()
                start()
            }
            updateChipStyle(newChip, true)
        }

        currentFilter = type
        applyFilter()
    }

    /**
     * Creates the RecyclerView for displaying the certificate list.
     */
    private fun buildCertificateList() {
        adapter = CertificateListAdapter()

        recyclerView = RecyclerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            layoutManager = LinearLayoutManager(this@CertificateManagementActivity)
            this.adapter = this@CertificateManagementActivity.adapter
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 4),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 88)
            )
            clipToPadding = false

            addOnScrollListener(object : RecyclerView.OnScrollListener() {
                override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                    if (dy > 0 && isFabVisible) {
                        hideFab()
                    } else if (dy < 0 && !isFabVisible) {
                        showFab()
                    }
                }
            })
        }

        recyclerView.itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator().apply {
            addDuration = 200
            removeDuration = 200
            moveDuration = 200
            changeDuration = 200
        }

        contentLayout.addView(recyclerView)
    }

    /**
     * Creates the empty state view with icon and description.
     */
    private fun buildEmptyState() {
        emptyStateContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            visibility = View.GONE
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 48),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 48),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 48),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 48)
            )
        }

        val emptyIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_certificate)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@CertificateManagementActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 96),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.cert_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@CertificateManagementActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 8)
            }
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.cert_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@CertificateManagementActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 32)
            }
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        contentLayout.addView(emptyStateContainer)
    }

    /**
     * Creates the floating action button for issuing certificates.
     */
    private fun buildFab() {
        fab = ExtendedFloatingActionButton(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.BOTTOM or Gravity.END
                setMargins(
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                    UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16)
                )
            }
            text = getString(R.string.cert_issue_title)
            setIconResource(android.R.drawable.ic_input_add)
            backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@CertificateManagementActivity, R.color.secondary)
            )
            setTextColor(ContextCompat.getColor(
                this@CertificateManagementActivity,
                R.color.on_secondary
            ))
            iconTint = ColorStateList.valueOf(
                ContextCompat.getColor(this@CertificateManagementActivity, R.color.on_secondary)
            )
            setOnClickListener {
                showIssueCertificateDialog()
            }
        }
    }

    /**
     * Shows the FAB with animation.
     */
    private fun showFab() {
        isFabVisible = true
        fab.extend()
        fab.animate()
            .translationY(0f)
            .alpha(1f)
            .setDuration(FAB_ANIMATION_DURATION)
            .start()
    }

    /**
     * Hides the FAB with animation.
     */
    private fun hideFab() {
        isFabVisible = false
        fab.shrink()
        fab.animate()
            .translationY(UIHelpers.dpToPx(this, 100f))
            .alpha(0f)
            .setDuration(FAB_ANIMATION_DURATION)
            .start()
    }

    // -------------------------------------------------------------------------
    // Data Management
    // -------------------------------------------------------------------------

    /**
     * Observes all certificates reactively and updates the UI on changes.
     */
    private fun observeCertificates() {
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                certificateDao.observeAll().collectLatest { certificates ->
                    allCertificates = certificates
                    applyFilter()
                    updateSummaryCard()
                }
            }
        }
    }

    /**
     * Applies the current filter and updates the adapter.
     */
    private fun applyFilter() {
        val now = System.currentTimeMillis()
        val filtered = when (currentFilter) {
            null -> allCertificates
            FILTER_REVOKED -> allCertificates.filter { it.revoked }
            FILTER_EXPIRED -> allCertificates.filter { it.notAfter < now && !it.revoked }
            FILTER_TLS_SERVER -> allCertificates.filter { it.profile == FILTER_TLS_SERVER }
            FILTER_TLS_CLIENT -> allCertificates.filter { it.profile == FILTER_TLS_CLIENT }
            FILTER_IDEVID -> allCertificates.filter { it.profile == FILTER_IDEVID }
            FILTER_CODE_SIGNING -> allCertificates.filter { it.profile == FILTER_CODE_SIGNING }
            FILTER_EMAIL -> allCertificates.filter { it.profile == FILTER_EMAIL }
            FILTER_OCSP -> allCertificates.filter { it.profile == FILTER_OCSP }
            FILTER_TIMESTAMPING -> allCertificates.filter { it.profile == FILTER_TIMESTAMPING }
            FILTER_CA -> allCertificates.filter { it.isCA || it.profile == FILTER_CA }
            else -> allCertificates
        }
        adapter.submitList(filtered)

        if (filtered.isEmpty()) {
            recyclerView.visibility = View.GONE
            emptyStateContainer.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyStateContainer.visibility = View.GONE
        }
    }

    /**
     * Updates the hero summary card with certificate statistics.
     */
    private fun updateSummaryCard() {
        val total = allCertificates.size
        totalCountText.text = total.toString()
        totalLabelText.text = getString(R.string.cert_summary_total)

        badgeContainer.removeAllViews()

        val now = System.currentTimeMillis()
        val expiredCount = allCertificates.count { it.notAfter < now && !it.revoked }
        val expiringCount = allCertificates.count {
            !it.revoked && it.notAfter >= now && it.notAfter < now + EXPIRING_SOON_THRESHOLD_MS
        }
        val revokedCount = allCertificates.count { it.revoked }

        if (expiredCount > 0) {
            val color = ContextCompat.getColor(this, android.R.color.holo_red_light)
            badgeContainer.addView(
                createSummaryBadge(
                    "$expiredCount ${getString(R.string.cert_summary_expired)}",
                    color
                )
            )
        }

        if (expiringCount > 0) {
            val color = ContextCompat.getColor(this, android.R.color.holo_orange_light)
            badgeContainer.addView(
                createSummaryBadge(
                    "$expiringCount ${getString(R.string.cert_summary_expiring)}",
                    color
                )
            )
        }

        if (revokedCount > 0) {
            val color = ContextCompat.getColor(this, android.R.color.darker_gray)
            badgeContainer.addView(
                createSummaryBadge(
                    "$revokedCount ${getString(R.string.cert_summary_revoked)}",
                    color
                )
            )
        }
    }

    // -------------------------------------------------------------------------
    // Certificate Operations
    // -------------------------------------------------------------------------

    /**
     * Shows the context menu for a certificate.
     */
    private fun showCertificateContextMenu(cert: CertificateEntity, anchorView: View) {
        PopupMenu(this, anchorView, Gravity.END).apply {
            menu.add(Menu.NONE, MENU_VIEW_DETAILS, 0, R.string.cert_detail_title)
            menu.add(Menu.NONE, MENU_EXPORT_PEM, 1, R.string.cert_export_action)
            if (!cert.revoked) {
                menu.add(Menu.NONE, MENU_REVOKE, 2, R.string.cert_revoke_title)
            }
            menu.add(Menu.NONE, MENU_DELETE, 3, R.string.cert_delete_title)

            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    MENU_VIEW_DETAILS -> {
                        showCertificateDetails(cert)
                        true
                    }
                    MENU_EXPORT_PEM -> {
                        exportCertificatePEM(cert)
                        true
                    }
                    MENU_REVOKE -> {
                        showRevokeConfirmation(cert)
                        true
                    }
                    MENU_DELETE -> {
                        showDeleteConfirmation(cert)
                        true
                    }
                    else -> false
                }
            }
            show()
        }
    }

    /**
     * Opens the certificate detail activity for a certificate.
     */
    private fun showCertificateDetails(cert: CertificateEntity) {
        val intent = android.content.Intent(this, CertificateDetailActivity::class.java).apply {
            putExtra(CertificateDetailActivity.EXTRA_SERIAL_NUMBER, cert.serialNumber)
        }
        startActivity(intent)
    }

    /**
     * Exports certificate PEM to the clipboard.
     */
    private fun exportCertificatePEM(cert: CertificateEntity) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Certificate PEM", cert.certificatePEM))

        AuditLogger.logCertificateExported(
            serialNumber = cert.serialNumber,
            subjectDN = cert.subjectDN,
            format = "PEM"
        )

        Snackbar.make(
            rootLayout,
            getString(R.string.cert_export_copied),
            Snackbar.LENGTH_SHORT
        ).show()
    }

    /**
     * Shows the revocation confirmation dialog.
     */
    private fun showRevokeConfirmation(cert: CertificateEntity) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.cert_revoke_title))
            .setMessage(getString(R.string.cert_revoke_message))
            .setPositiveButton(getString(R.string.cert_revoke_confirm)) { _, _ ->
                revokeCertificate(cert)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Revokes a certificate.
     */
    private fun revokeCertificate(cert: CertificateEntity) {
        lifecycleScope.launch {
            try {
                certificateDao.revoke(
                    cert.serialNumber,
                    System.currentTimeMillis(),
                    AndroidCA.CRLReason.UNSPECIFIED
                )

                AuditLogger.logCertificateRevoked(
                    serialNumber = cert.serialNumber,
                    subjectDN = cert.subjectDN,
                    reason = AndroidCA.CRLReason.UNSPECIFIED
                )

                Snackbar.make(
                    rootLayout,
                    getString(R.string.cert_revoke_success),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                android.util.Log.e("CertManagement", "Certificate revocation failed", e)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.cert_revoke_error, e.message ?: "Unknown error"),
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * Shows the delete confirmation dialog.
     */
    private fun showDeleteConfirmation(cert: CertificateEntity) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.cert_delete_title))
            .setMessage(getString(R.string.cert_delete_message))
            .setPositiveButton(getString(R.string.cert_delete_confirm)) { _, _ ->
                deleteCertificate(cert)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    /**
     * Deletes a certificate record.
     */
    private fun deleteCertificate(cert: CertificateEntity) {
        lifecycleScope.launch {
            try {
                certificateDao.deleteBySerial(cert.serialNumber)
                TrustStoreRepository(this@CertificateManagementActivity).deleteCertificate(cert.fingerprint)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.cert_delete_success),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                android.util.Log.e("CertManagement", "Certificate deletion failed", e)
                Snackbar.make(
                    rootLayout,
                    "Failed to delete certificate",
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    // -------------------------------------------------------------------------
    // Certificate Issuance
    // -------------------------------------------------------------------------

    private data class ProfileOption(
        val display: String,
        val profileName: String,
        val defaultValidityDays: Int,
        val showSans: Boolean,
        val sansHint: Int?
    )

    private fun buildProfileOptions(): List<ProfileOption> = listOf(
        ProfileOption(getString(R.string.cert_filter_tls_server), "tls-server", 365, true, R.string.cert_issue_sans_hint),
        ProfileOption(getString(R.string.cert_filter_tls_client), "tls-client", 365, true, R.string.cert_issue_email_hint),
        ProfileOption(getString(R.string.cert_filter_idevid), "idevid", 365, false, null),
        ProfileOption(getString(R.string.cert_filter_code_signing), "code-signing", 365, false, null),
        ProfileOption(getString(R.string.cert_filter_email), "email", 365, true, R.string.cert_issue_email_hint),
        ProfileOption(getString(R.string.cert_filter_ocsp), "ocsp-responder", 90, false, null),
        ProfileOption(getString(R.string.cert_filter_timestamping), "timestamping", 365, false, null),
        ProfileOption(getString(R.string.cert_filter_ca), "subordinate-ca", 1825, false, null)
    )

    private fun showIssueCertificateDialog() {
        val profiles = buildProfileOptions()

        val dialogLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 24),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 16),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 24),
                UIHelpers.dpToPxInt(this@CertificateManagementActivity, 8)
            )
        }

        // Profile spinner
        val profileLabel = TextView(this).apply {
            text = getString(R.string.cert_issue_profile)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
        }
        dialogLayout.addView(profileLabel)

        val profileSpinner = Spinner(this)
        val profileAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            profiles.map { it.display }
        )
        profileAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        profileSpinner.adapter = profileAdapter
        dialogLayout.addView(profileSpinner)

        // Subject CN
        val cnLabel = TextView(this).apply {
            text = getString(R.string.cert_issue_subject_cn)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12)
            }
        }
        dialogLayout.addView(cnLabel)

        val cnInput = EditText(this).apply {
            hint = getString(R.string.cert_issue_subject_cn_hint)
            setSingleLine()
        }
        dialogLayout.addView(cnInput)

        // Organization
        val orgLabel = TextView(this).apply {
            text = getString(R.string.cert_issue_organization)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12)
            }
        }
        dialogLayout.addView(orgLabel)

        val orgInput = EditText(this).apply {
            hint = getString(R.string.cert_issue_organization_hint)
            setSingleLine()
        }
        dialogLayout.addView(orgInput)

        // Validity days
        val validityLabel = TextView(this).apply {
            text = getString(R.string.cert_issue_validity_days)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12)
            }
        }
        dialogLayout.addView(validityLabel)

        val validityInput = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(profiles[0].defaultValidityDays.toString())
            setSingleLine()
        }
        dialogLayout.addView(validityInput)

        // SANs
        val sansLabel = TextView(this).apply {
            text = getString(R.string.cert_issue_sans)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@CertificateManagementActivity, 12)
            }
        }
        dialogLayout.addView(sansLabel)

        val sansInput = EditText(this).apply {
            hint = getString(R.string.cert_issue_sans_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 2
            maxLines = 4
            gravity = Gravity.TOP or Gravity.START
        }
        dialogLayout.addView(sansInput)

        // Update SANs visibility and validity based on profile selection
        fun updateForProfile(position: Int) {
            val profile = profiles[position]
            validityInput.setText(profile.defaultValidityDays.toString())
            if (profile.showSans) {
                sansLabel.visibility = View.VISIBLE
                sansInput.visibility = View.VISIBLE
                profile.sansHint?.let { sansInput.hint = getString(it) }
            } else {
                sansLabel.visibility = View.GONE
                sansInput.visibility = View.GONE
            }
        }
        updateForProfile(0)

        profileSpinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, pos: Int, id: Long) {
                updateForProfile(pos)
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        val scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            addView(dialogLayout)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.cert_issue_title))
            .setView(scrollView)
            .setPositiveButton(getString(R.string.cert_issue_title)) { _, _ ->
                val profile = profiles[profileSpinner.selectedItemPosition]
                val cn = cnInput.text.toString().trim()
                val org = orgInput.text.toString().trim()
                val validityDays = validityInput.text.toString().toIntOrNull() ?: profile.defaultValidityDays
                val sansText = sansInput.text.toString().trim()
                issueCertificate(profile, cn, org, validityDays, sansText)
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    private fun issueCertificate(
        profile: ProfileOption,
        cn: String,
        org: String,
        validityDays: Int,
        sansText: String
    ) {
        lifecycleScope.launch {
            try {
                if (!androidCA.isInitialized()) {
                    MaterialAlertDialogBuilder(this@CertificateManagementActivity)
                        .setTitle(getString(R.string.cert_ca_not_initialized_title))
                        .setMessage(getString(R.string.cert_ca_not_initialized_message))
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                    return@launch
                }

                val keyId = UUID.randomUUID().toString()
                val keystoreAlias = "xkey_key_$keyId"
                // In the store's one serialisation of this id's key material (#193 r8).
                val publicKeyDer = keyPolicyStore.withKeyMaterial(keyId) {
                    withContext(Dispatchers.IO) {
                        keystoreManager.generateKeyForAlgorithm(keyId, "ES256", -1)
                    }
                }

                // The signing key now exists, but the certificate that gives it
                // a purpose does not. Everything from here on can throw --- a
                // subject the DN parser refuses, a CSR that will not build, a CA
                // that will not sign --- and none of it cleans up after itself,
                // so an orphaned alias and key row would survive with nothing
                // pointing at them and nothing to notice.
                try {
                    val keyEntity = KeyEntity(
                        keyId = keyId,
                        keyType = "signing",
                        algorithm = "ES256",
                        label = "$cn (${profile.display})",
                        publicKeyDer = publicKeyDer,
                        keySizeBits = 256,
                        biometricRequired = false,
                        source = "local"
                    )
                    withContext(Dispatchers.IO) {
                        keyDao.insert(keyEntity)
                    }

                    val subjectParts = mutableListOf("CN=$cn")
                    if (org.isNotEmpty()) subjectParts.add("O=$org")
                    val x500Name = X500Name(subjectParts.joinToString(", "))

                    val csrDER = withContext(Dispatchers.IO) {
                        androidCA.createCSR(x500Name, keystoreAlias)
                    }

                    val certProfile = when (profile.profileName) {
                        "tls-server" -> {
                            val (dnsNames, ipAddresses) = parseSANs(sansText, isEmail = false)
                            CertificateProfile.TLSServer(validityDays, dnsNames, ipAddresses)
                        }
                        "tls-client" -> {
                            val (emails, _) = parseSANs(sansText, isEmail = true)
                            CertificateProfile.TLSClient(validityDays, emails)
                        }
                        "email" -> {
                            val (emails, _) = parseSANs(sansText, isEmail = true)
                            CertificateProfile.Email(validityDays, emails)
                        }
                        "idevid" -> CertificateProfile.IDevID(validityDays)
                        "code-signing" -> CertificateProfile.CodeSigning(validityDays)
                        "ocsp-responder" -> CertificateProfile.OCSPResponder(validityDays)
                        "timestamping" -> CertificateProfile.Timestamping(validityDays)
                        "subordinate-ca" -> CertificateProfile.SubordinateCA(validityDays)
                        else -> CertificateProfile.TLSServer(validityDays)
                    }

                    withContext(Dispatchers.IO) {
                        androidCA.issueCertificate(csrDER, certProfile, x500Name)
                    }
                } catch (e: Exception) {
                    discardIssuanceKey(keyId, keystoreAlias)
                    throw e
                }

                Snackbar.make(
                    rootLayout,
                    getString(R.string.cert_issue_success),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                android.util.Log.e("CertManagement", "Certificate issuance failed", e)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.cert_issue_error, e.message ?: "Unknown error"),
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * Removes the key an abandoned issuance left behind.
     *
     * Deleting by raw alias rather than through [KeystoreManager.deleteGeneralKey]
     * keeps a key the user never saw out of the audit log. A rollback that itself
     * fails is logged and swallowed: the caller is on its way to reporting the
     * failure that started this, and that is the one worth showing.
     */
    private suspend fun discardIssuanceKey(keyId: String, keystoreAlias: String) {
        try {
            keyPolicyStore.withKeyMaterial(keyId) {
                withContext(Dispatchers.IO) {
                    keyDao.deleteByKeyId(keyId)
                    keystoreManager.deleteByAlias(keystoreAlias)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("CertManagement", "Rollback of key $keyId failed", e)
        }
    }

    private fun parseSANs(text: String, isEmail: Boolean): Pair<List<String>, List<String>> {
        if (text.isBlank()) return Pair(emptyList(), emptyList())
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (isEmail) {
            return Pair(lines, emptyList())
        }
        val ipRegex = Regex("""^\d+\.\d+\.\d+\.\d+$|^.*:.*:.*$""")
        val dnsNames = mutableListOf<String>()
        val ipAddresses = mutableListOf<String>()
        for (line in lines) {
            if (ipRegex.matches(line)) {
                ipAddresses.add(line)
            } else {
                dnsNames.add(line)
            }
        }
        return Pair(dnsNames, ipAddresses)
    }

    // -------------------------------------------------------------------------
    // Certificate Helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts the Common Name (CN) from a distinguished name string.
     */
    private fun extractCN(subjectDN: String): String {
        return CN_REGEX.find(subjectDN)?.groupValues?.getOrNull(1) ?: subjectDN
    }

    /**
     * Returns the certificate status for display.
     */
    private fun getCertificateStatus(cert: CertificateEntity): CertStatus {
        val now = System.currentTimeMillis()
        return when {
            cert.revoked -> CertStatus.REVOKED
            cert.notAfter < now -> CertStatus.EXPIRED
            cert.notAfter < now + EXPIRING_SOON_THRESHOLD_MS -> CertStatus.EXPIRING_SOON
            cert.isCA -> CertStatus.CA
            else -> CertStatus.VALID
        }
    }

    /**
     * Returns the status color for a certificate status.
     */
    private fun getStatusColor(status: CertStatus): Int = when (status) {
        CertStatus.VALID -> ContextCompat.getColor(this, android.R.color.holo_green_dark)
        CertStatus.EXPIRED -> ContextCompat.getColor(this, android.R.color.holo_red_light)
        CertStatus.EXPIRING_SOON -> ContextCompat.getColor(this, android.R.color.holo_orange_light)
        CertStatus.REVOKED -> ContextCompat.getColor(this, android.R.color.darker_gray)
        CertStatus.CA -> ContextCompat.getColor(this, android.R.color.holo_blue_dark)
    }

    /**
     * Returns the status display string for a certificate status.
     */
    private fun getStatusText(status: CertStatus): String = when (status) {
        CertStatus.VALID -> getString(R.string.cert_status_valid)
        CertStatus.EXPIRED -> getString(R.string.cert_status_expired)
        CertStatus.EXPIRING_SOON -> getString(R.string.cert_status_expiring)
        CertStatus.REVOKED -> getString(R.string.cert_status_revoked)
        CertStatus.CA -> getString(R.string.cert_status_ca)
    }

    /**
     * Returns a human-readable display name for a certificate profile.
     */
    private fun getProfileDisplayName(profile: String): String = when (profile) {
        "tls-server" -> getString(R.string.cert_filter_tls_server)
        "tls-client" -> getString(R.string.cert_filter_tls_client)
        "idevid" -> getString(R.string.cert_filter_idevid)
        "code-signing" -> getString(R.string.cert_filter_code_signing)
        "email" -> getString(R.string.cert_filter_email)
        "ocsp-responder" -> getString(R.string.cert_filter_ocsp)
        "timestamping" -> getString(R.string.cert_filter_timestamping)
        "subordinate-ca" -> getString(R.string.cert_filter_ca)
        else -> profile.replaceFirstChar { it.uppercase() }
    }

    /**
     * Returns the icon resource ID for a certificate profile.
     */
    private fun getProfileIconRes(profile: String): Int = when (profile) {
        "tls-server" -> R.drawable.ic_certificate
        "tls-client" -> R.drawable.ic_certificate
        "idevid" -> R.drawable.ic_certificate
        "code-signing" -> R.drawable.ic_certificate
        "email" -> R.drawable.ic_certificate
        "ocsp-responder" -> R.drawable.ic_certificate
        "timestamping" -> R.drawable.ic_certificate
        "subordinate-ca" -> R.drawable.ic_certificate
        else -> R.drawable.ic_certificate
    }

    /**
     * Returns the gradient colors for a certificate profile.
     */
    private fun getProfileGradient(profile: String): Pair<Int, Int> = when (profile) {
        "tls-server" -> Pair(
            ContextCompat.getColor(this, R.color.primary_40),
            ContextCompat.getColor(this, R.color.primary_60)
        )
        "tls-client" -> Pair(
            ContextCompat.getColor(this, R.color.tertiary_40),
            ContextCompat.getColor(this, R.color.tertiary_60)
        )
        "idevid" -> Pair(
            ContextCompat.getColor(this, R.color.security_verified_variant),
            ContextCompat.getColor(this, R.color.security_verified)
        )
        "code-signing" -> Pair(
            ContextCompat.getColor(this, R.color.tertiary_30),
            ContextCompat.getColor(this, R.color.tertiary_50)
        )
        "email" -> Pair(
            ContextCompat.getColor(this, R.color.primary_50),
            ContextCompat.getColor(this, R.color.primary_70)
        )
        "ocsp-responder" -> Pair(
            ContextCompat.getColor(this, R.color.secondary_60),
            ContextCompat.getColor(this, R.color.secondary_70)
        )
        "timestamping" -> Pair(
            ContextCompat.getColor(this, R.color.tertiary_50),
            ContextCompat.getColor(this, R.color.tertiary_70)
        )
        "subordinate-ca" -> Pair(
            ContextCompat.getColor(this, R.color.primary_20),
            ContextCompat.getColor(this, R.color.primary_40)
        )
        else -> Pair(
            ContextCompat.getColor(this, R.color.primary_40),
            ContextCompat.getColor(this, R.color.primary_60)
        )
    }

    /**
     * Formats a hex fingerprint into colon-separated uppercase pairs.
     */
    private fun formatFingerprint(fingerprint: String): String {
        return fingerprint.uppercase().chunked(2).joinToString(":")
    }

    // -------------------------------------------------------------------------
    // Certificate Status Enum
    // -------------------------------------------------------------------------

    /**
     * Represents the display status of a certificate.
     */
    private enum class CertStatus {
        VALID,
        EXPIRED,
        EXPIRING_SOON,
        REVOKED,
        CA
    }

    // -------------------------------------------------------------------------
    // RecyclerView Adapter
    // -------------------------------------------------------------------------

    /**
     * RecyclerView adapter for certificate cards using DiffUtil.
     */
    inner class CertificateListAdapter :
        ListAdapter<CertificateEntity, CertificateListAdapter.ViewHolder>(CertificateDiffCallback()) {

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            return ViewHolder(buildCertificateCard(parent.context))
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(getItem(position))
        }

        /**
         * Builds a certificate card layout programmatically.
         */
        private fun buildCertificateCard(context: Context): MaterialCardView {
            val card = PremiumCardFactory.createElevatedCard(context).apply {
                (layoutParams as LinearLayout.LayoutParams).apply {
                    setMargins(
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 6),
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 6)
                    )
                }
            }

            val content = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                setPadding(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 14),
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 14)
                )
                gravity = Gravity.CENTER_VERTICAL
            }

            // Circular icon container with gradient
            val iconContainer = FrameLayout(context).apply {
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 48),
                    UIHelpers.dpToPxInt(context, 48)
                ).apply {
                    marginEnd = UIHelpers.dpToPxInt(context, 14)
                }
                tag = "iconContainer"
            }

            val iconView = ImageView(context).apply {
                layoutParams = FrameLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 28),
                    UIHelpers.dpToPxInt(context, 28)
                ).apply {
                    gravity = Gravity.CENTER
                }
                imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(context, R.color.on_primary)
                )
                tag = "icon"
            }

            iconContainer.addView(iconView)
            content.addView(iconContainer)

            // Info column
            val infoColumn = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f
                )
            }

            val subjectText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_TitleMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                tag = "subject"
            }
            infoColumn.addView(subjectText)

            // Profile and validity row
            val metaRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 2)
                }
                gravity = Gravity.CENTER_VERTICAL
            }

            val profileText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    androidx.appcompat.R.attr.colorPrimary
                ))
                typeface = Typeface.DEFAULT_BOLD
                tag = "profile"
            }
            metaRow.addView(profileText)

            val separatorText = TextView(context).apply {
                text = "  \u2022  "
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
            }
            metaRow.addView(separatorText)

            val validityText = TextView(context).apply {
                setTextAppearance(
                    com.google.android.material.R.style.TextAppearance_Material3_LabelMedium
                )
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                tag = "validity"
            }
            metaRow.addView(validityText)
            infoColumn.addView(metaRow)

            // Badges row
            val badgeRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 6)
                }
                tag = "badgeRow"
            }
            infoColumn.addView(badgeRow)

            content.addView(infoColumn)

            // Chevron
            val chevron = ImageView(context).apply {
                setImageResource(R.drawable.ic_chevron_right)
                imageTintList = ColorStateList.valueOf(
                    UIHelpers.resolveThemeColor(
                        context,
                        com.google.android.material.R.attr.colorOutlineVariant
                    )
                )
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 24),
                    UIHelpers.dpToPxInt(context, 24)
                )
            }
            content.addView(chevron)

            card.addView(content)
            return card
        }

        inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

            private val iconContainer: FrameLayout = itemView.findViewWithTag("iconContainer")
            private val iconView: ImageView = itemView.findViewWithTag("icon")
            private val subjectView: TextView = itemView.findViewWithTag("subject")
            private val profileView: TextView = itemView.findViewWithTag("profile")
            private val validityView: TextView = itemView.findViewWithTag("validity")
            private val badgeRow: LinearLayout = itemView.findViewWithTag("badgeRow")

            fun bind(cert: CertificateEntity) {
                // Set icon with gradient background
                iconView.setImageResource(getProfileIconRes(cert.profile))
                val (gradientStart, gradientEnd) = getProfileGradient(cert.profile)
                val gradient = GradientDrawable(
                    GradientDrawable.Orientation.TL_BR,
                    intArrayOf(gradientStart, gradientEnd)
                )
                gradient.cornerRadius = UIHelpers.dpToPx(itemView.context, 24f)
                iconContainer.background = gradient

                // Set text fields
                subjectView.text = extractCN(cert.subjectDN)
                profileView.text = getProfileDisplayName(cert.profile)
                validityView.text = "${dateFormat.format(Date(cert.notBefore))} - ${dateFormat.format(Date(cert.notAfter))}"

                // Build status badges
                badgeRow.removeAllViews()

                val status = getCertificateStatus(cert)
                badgeRow.addView(createCertBadge(
                    getStatusText(status),
                    getStatusColor(status),
                    ContextCompat.getColor(itemView.context, R.color.on_primary)
                ))

                // Add CA badge if this is a CA cert but not already showing CA status
                if (cert.isCA && status != CertStatus.CA) {
                    badgeRow.addView(createCertBadge(
                        getString(R.string.cert_status_ca),
                        ContextCompat.getColor(itemView.context, android.R.color.holo_blue_dark),
                        ContextCompat.getColor(itemView.context, R.color.on_primary)
                    ))
                }

                // Click handlers
                itemView.setOnClickListener {
                    showCertificateDetails(cert)
                }
                itemView.setOnLongClickListener {
                    showCertificateContextMenu(cert, itemView)
                    true
                }
            }

            private fun createCertBadge(text: String, bgColor: Int, textColor: Int): TextView {
                return TextView(itemView.context).apply {
                    this.text = text
                    textSize = 10f
                    setTextColor(textColor)
                    setPadding(
                        UIHelpers.dpToPxInt(context, 8),
                        UIHelpers.dpToPxInt(context, 3),
                        UIHelpers.dpToPxInt(context, 8),
                        UIHelpers.dpToPxInt(context, 3)
                    )
                    background = UIHelpers.createRoundedDrawable(
                        bgColor,
                        UIHelpers.dpToPx(context, 10f)
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply {
                        marginEnd = UIHelpers.dpToPxInt(context, 6)
                    }
                }
            }
        }
    }

    /**
     * DiffUtil callback for efficient certificate list updates.
     */
    class CertificateDiffCallback : DiffUtil.ItemCallback<CertificateEntity>() {
        override fun areItemsTheSame(
            oldItem: CertificateEntity,
            newItem: CertificateEntity
        ): Boolean {
            return oldItem.serialNumber == newItem.serialNumber
        }

        override fun areContentsTheSame(
            oldItem: CertificateEntity,
            newItem: CertificateEntity
        ): Boolean {
            return oldItem == newItem
        }
    }
}
