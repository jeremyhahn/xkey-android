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

import android.animation.ObjectAnimator
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.annotation.ColorInt
import androidx.annotation.ColorRes
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.coordinatorlayout.widget.CoordinatorLayout
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.automatethethings.xkey.storage.dao.deleteKeyAndMaterial
import com.google.android.material.appbar.AppBarLayout
import com.google.android.material.appbar.CollapsingToolbarLayout
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.snackbar.Snackbar
import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.abs

/**
 * Premium key details activity with elegant, professional UI design.
 *
 * Features a collapsing toolbar with gradient hero section, premium info cards
 * with visual security indicators, and polished animations. The design treats
 * keys as premium digital assets worthy of elegant presentation.
 *
 * Layout architecture:
 * - CoordinatorLayout root for scroll coordination
 * - AppBarLayout with CollapsingToolbarLayout for hero effect
 * - NestedScrollView with premium card sections
 * - Bottom sheet for confirmations
 *
 * The key ID is passed via the [EXTRA_KEY_ID] intent extra.
 */
class KeyDetailActivity : AppCompatActivity() {

    companion object {
        /** Intent extra key for the key identifier string. */
        const val EXTRA_KEY_ID = "key_id"

        /** OID for Android Key Attestation extension. */
        private const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /** Security level integer to name mapping from the Android attestation spec. */
        private val securityLevelNames = mapOf(
            0 to "Software",
            1 to "TEE",
            2 to "StrongBox"
        )

        /** Key type to gradient colors mapping. */

        /** Key type to icon mapping. */
        private val keyTypeIcons = mapOf(
            "fido2" to "\uD83D\uDD11",
            "signing" to "\u270D\uFE0F",
            "encryption" to "\uD83D\uDEE1\uFE0F",
            "tls" to "\uD83D\uDD12",
            "ssh" to "\uD83D\uDCBB",
            "secret" to "\uD83D\uDD10",
            "hmac" to "\u2714\uFE0F",
            "ca" to "\uD83C\uDFDB\uFE0F",
            "attestation" to "\uD83D\uDCDC"
        )
    }

    private val keyDao by lazy { XKeyDatabase.getInstance(this).keyDao() }
    private val keySharingPolicyDao: KeySharingPolicyDao by lazy {
        XKeyDatabase.getInstance(this).keySharingPolicyDao()
    }
    private val keystoreManager by lazy { KeystoreManager(this) }

    private lateinit var coordinatorLayout: CoordinatorLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var heroIconContainer: LinearLayout
    private lateinit var heroTitleText: TextView
    private lateinit var heroSubtitleContainer: LinearLayout
    private var currentKeyId: String? = null
    private var attestationContentLayout: LinearLayout? = null
    private var attestButton: MaterialButton? = null
    private var attestProgress: ProgressBar? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val keyId = intent.getStringExtra(EXTRA_KEY_ID) ?: run {
            finish()
            return
        }

        currentKeyId = keyId
        buildPremiumLayout()
        observeKeyDetails(keyId)
    }

    /**
     * Renders the key and re-renders it whenever the row changes.
     *
     * Replaces a pair of loads from `onCreate` and `onResume`, which queried and
     * built the whole content twice on every launch, and left the hero section
     * out of the refresh entirely. Observing also covers the case `onResume`
     * never could: the sharing bottom sheet is a dialog fragment, so dismissing
     * it does not stop the activity and the sharing badge stayed stale.
     */
    private fun observeKeyDetails(keyId: String) {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                var rendered = false
                keyDao.observeByKeyId(keyId).collectLatest { key ->
                    if (key == null) {
                        finish()
                        return@collectLatest
                    }
                    updateHeroSection(key)
                    contentLayout.removeAllViews()
                    displayKeyDetails(key)
                    if (!rendered) {
                        rendered = true
                        animateContentIn()
                    }
                }
            }
        }
    }

    /**
     * Builds the premium layout with CoordinatorLayout and collapsing toolbar.
     */
    private fun buildPremiumLayout() {
        coordinatorLayout = CoordinatorLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(resolveThemeColor(android.R.attr.colorBackground))
        }

        buildAppBar()
        buildScrollContent()

        setContentView(coordinatorLayout)
    }

    /**
     * Builds the collapsing app bar with gradient hero section.
     */
    private fun buildAppBar() {
        val appBarLayout = AppBarLayout(this).apply {
            layoutParams = CoordinatorLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPxInt(220)
            )
            setBackgroundColor(Color.TRANSPARENT)
        }

        val collapsingToolbar = CollapsingToolbarLayout(this).apply {
            layoutParams = AppBarLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            ).apply {
                scrollFlags = AppBarLayout.LayoutParams.SCROLL_FLAG_SCROLL or
                        AppBarLayout.LayoutParams.SCROLL_FLAG_EXIT_UNTIL_COLLAPSED
            }
            setContentScrimColor(resolveThemeColor(com.google.android.material.R.attr.colorSurface))
            setExpandedTitleTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineMedium)
            setCollapsedTitleTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleLarge)
        }

        // Hero content container
        val heroContainer = LinearLayout(this).apply {
            layoutParams = CollapsingToolbarLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            ).apply {
                collapseMode = CollapsingToolbarLayout.LayoutParams.COLLAPSE_MODE_PARALLAX
            }
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dpToPxInt(24), dpToPxInt(56), dpToPxInt(24), dpToPxInt(16))
        }

        // Icon container with circular gradient background
        heroIconContainer = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPxInt(72), dpToPxInt(72)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(12)
            }
            gravity = Gravity.CENTER
            // Background will be set when key loads
        }

        val heroIcon = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            textSize = 32f
            gravity = Gravity.CENTER
            tag = "hero_icon"
        }
        heroIconContainer.addView(heroIcon)
        heroContainer.addView(heroIconContainer)

        // Title
        heroTitleText = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(8)
            }
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            gravity = Gravity.CENTER
            maxLines = 2
        }
        heroContainer.addView(heroTitleText)

        // Badges container
        heroSubtitleContainer = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }
        heroContainer.addView(heroSubtitleContainer)

        collapsingToolbar.addView(heroContainer)

        // Toolbar
        val toolbar = Toolbar(this).apply {
            layoutParams = CollapsingToolbarLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                resolveActionBarSize()
            ).apply {
                collapseMode = CollapsingToolbarLayout.LayoutParams.COLLAPSE_MODE_PIN
            }
            elevation = 0f
        }

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
            setDisplayShowTitleEnabled(false)
        }

        collapsingToolbar.addView(toolbar)
        appBarLayout.addView(collapsingToolbar)
        coordinatorLayout.addView(appBarLayout)

        // Add scroll listener for fade effects
        appBarLayout.addOnOffsetChangedListener { appBar, verticalOffset ->
            val scrollRange = appBar.totalScrollRange
            val alpha = 1f - abs(verticalOffset).toFloat() / scrollRange
            heroContainer.alpha = alpha
        }
    }

    /**
     * Builds the scrollable content area with NestedScrollView.
     */
    private fun buildScrollContent() {
        val scrollView = NestedScrollView(this).apply {
            layoutParams = CoordinatorLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            ).apply {
                behavior = AppBarLayout.ScrollingViewBehavior()
            }
            clipToPadding = false
        }

        contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(16), dpToPxInt(8), dpToPxInt(16), dpToPxInt(24))
        }

        scrollView.addView(contentLayout)
        coordinatorLayout.addView(scrollView)
    }

    /**
     * Loads the key entity and populates the view.
     */

    /**
     * Updates the hero section with key-specific styling.
     */
    private fun updateHeroSection(key: KeyEntity) {
        // Set icon
        val iconView = heroIconContainer.findViewWithTag<TextView>("hero_icon")
        iconView?.text = keyTypeIcons[key.keyType] ?: "\uD83D\uDD11"

        // Set circular gradient background for icon container
        val gradientColors = CategoryPalette.keyGradient(this, key.keyType)

        val iconBackground = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            gradientColors
        ).apply {
            shape = GradientDrawable.OVAL
        }
        heroIconContainer.background = iconBackground

        // Set title
        heroTitleText.text = key.label

        // Add badges
        heroSubtitleContainer.removeAllViews()

        // Algorithm badge
        addHeroBadge(key.algorithm, gradientColors[0])

        // Type badge
        addHeroBadge(getKeyTypeDisplayName(key.keyType), gradientColors[1])
    }

    /**
     * Adds a badge to the hero subtitle container.
     */
    private fun addHeroBadge(text: String, color: Int) {
        val badge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(8)
            }
            this.text = text
            textSize = 12f
            setTextColor(Color.WHITE)
            setPadding(dpToPxInt(12), dpToPxInt(4), dpToPxInt(12), dpToPxInt(4))
            background = GradientDrawable().apply {
                setColor(UIHelpers.applyAlpha(color, 0.85f))
                cornerRadius = dpToPx(12f)
            }
        }
        heroSubtitleContainer.addView(badge)
    }

    /**
     * Animates the content cards into view.
     */
    private fun animateContentIn() {
        for (i in 0 until contentLayout.childCount) {
            val child = contentLayout.getChildAt(i)
            child.alpha = 0f
            child.translationY = dpToPx(24f)
            child.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(350)
                .setStartDelay(i * 60L)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    /**
     * Populates the content area with premium info cards.
     */
    private fun displayKeyDetails(key: KeyEntity) {
        buildGeneralInfoCard(key)
        buildSecurityPropertiesCard(key)
        buildUsageStatsCard(key)

        if (key.keyType == "fido2") {
            buildFido2MetadataCard(key)
            buildSharingCard(key)
        }

        buildAttestationCard(key)
        buildActionsCard(key)
    }

    // -------------------------------------------------------------------------
    // Premium Card Builders
    // -------------------------------------------------------------------------

    /**
     * Builds the General Information card with premium styling.
     */
    private fun buildGeneralInfoCard(key: KeyEntity) {
        val card = createPremiumCard(
            title = getString(R.string.key_section_general),
            icon = "\uD83D\uDCCB"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addPremiumDetailRow(content, getString(R.string.key_detail_id), key.keyId, isMonospace = true)
        addPremiumDetailRow(content, getString(R.string.key_detail_type), getKeyTypeDisplayName(key.keyType))
        addPremiumDetailRow(content, getString(R.string.key_detail_algorithm), key.algorithm)
        addPremiumDetailRow(content, getString(R.string.key_detail_key_size), "${key.keySizeBits} bits")
        addPremiumDetailRow(content, getString(R.string.key_detail_source), getSourceDisplayName(key.source))

        if (key.remoteBackend != null) {
            addPremiumDetailRow(content, getString(R.string.key_detail_remote_backend), key.remoteBackend)
        }

        contentLayout.addView(card)
    }

    /**
     * Builds the Security Properties card with visual indicators.
     */
    private fun buildSecurityPropertiesCard(key: KeyEntity) {
        val card = createPremiumCard(
            title = getString(R.string.key_section_security),
            icon = "\uD83D\uDEE1\uFE0F"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        // Security indicators row
        val indicatorsRow = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(16)
            }
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }

        // StrongBox indicator
        if (key.strongBoxBacked) {
            addSecurityIndicator(indicatorsRow, "\uD83D\uDEE1\uFE0F", "StrongBox", semanticColor(R.color.security_verified))
        }

        // Biometric indicator
        if (key.biometricRequired) {
            addSecurityIndicator(indicatorsRow, "\uD83D\uDD90\uFE0F", "Biometric", semanticColor(R.color.security_warning))
        }

        // Hardware-backed indicator
        if (!key.strongBoxBacked && key.source == "local") {
            addSecurityIndicator(indicatorsRow, "\uD83D\uDD12", "TEE", semanticColor(R.color.security_info))
        }

        if (indicatorsRow.childCount > 0) {
            content.addView(indicatorsRow)
        }

        // Detail rows
        addPremiumDetailRow(
            content,
            getString(R.string.key_detail_strongbox),
            if (key.strongBoxBacked) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
        )
        addPremiumDetailRow(
            content,
            getString(R.string.key_detail_biometric),
            if (key.biometricRequired) getString(R.string.key_detail_required) else getString(R.string.key_detail_not_required)
        )
        addPremiumDetailRow(
            content,
            getString(R.string.key_detail_auth_duration),
            "${key.authDurationSeconds}s"
        )
        addPremiumDetailRow(
            content,
            getString(R.string.key_detail_exportable),
            if (key.exportable) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
        )

        contentLayout.addView(card)
    }

    /**
     * Adds a visual security indicator badge.
     */
    private fun addSecurityIndicator(parent: LinearLayout, icon: String, label: String, color: Int) {
        val indicator = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(12)
            }
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dpToPxInt(12), dpToPxInt(8), dpToPxInt(12), dpToPxInt(8))
            background = GradientDrawable().apply {
                setColor(UIHelpers.applyAlpha(color, 0.15f))
                cornerRadius = dpToPx(12f)
            }
        }

        val iconView = TextView(this).apply {
            text = icon
            textSize = 16f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(6)
            }
        }
        indicator.addView(iconView)

        val labelView = TextView(this).apply {
            text = label
            textSize = 12f
            setTextColor(color)
            typeface = Typeface.DEFAULT_BOLD
        }
        indicator.addView(labelView)

        parent.addView(indicator)
    }

    /**
     * Builds the Usage Statistics card.
     */
    private fun buildUsageStatsCard(key: KeyEntity) {
        val card = createPremiumCard(
            title = getString(R.string.key_section_usage),
            icon = "\uD83D\uDCCA"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val dateFormat = SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault())

        // Created date with calendar icon
        addUsageRow(
            content,
            "\uD83D\uDCC5",
            getString(R.string.key_detail_created),
            dateFormat.format(Date(key.createdAt))
        )

        // Last used with clock icon
        val lastUsed = if (key.lastUsedAt > 0) {
            dateFormat.format(Date(key.lastUsedAt))
        } else {
            getString(R.string.key_detail_never)
        }
        addUsageRow(
            content,
            "\u23F0",
            getString(R.string.key_detail_last_used),
            lastUsed
        )

        // Use count with counter icon
        addUsageRow(
            content,
            "\uD83D\uDD22",
            getString(R.string.key_detail_use_count),
            key.useCount.toString()
        )

        contentLayout.addView(card)
    }

    /**
     * Adds a usage row with icon.
     */
    private fun addUsageRow(parent: LinearLayout, icon: String, label: String, value: String) {
        val row = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(12)
            }
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val iconView = TextView(this).apply {
            text = icon
            textSize = 18f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(12)
            }
        }
        row.addView(iconView)

        val labelView = TextView(this).apply {
            text = label
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
        }
        row.addView(labelView)

        val valueView = TextView(this).apply {
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            typeface = Typeface.DEFAULT_BOLD
        }
        row.addView(valueView)

        parent.addView(row)
    }

    /**
     * Builds the FIDO2 Metadata card.
     */
    private fun buildFido2MetadataCard(key: KeyEntity) {
        val card = createPremiumCard(
            title = getString(R.string.key_section_fido2),
            icon = "\uD83D\uDD11"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        // RP info with globe icon
        addUsageRow(content, "\uD83C\uDF10", getString(R.string.key_detail_rp_id), key.rpId ?: "-")
        addUsageRow(content, "\uD83C\uDFE2", getString(R.string.key_detail_rp_name), key.rpName ?: "-")

        // User info with person icon
        addUsageRow(content, "\uD83D\uDC64", getString(R.string.key_detail_user_name), key.userName ?: "-")
        addUsageRow(content, "\uD83D\uDCDB", getString(R.string.key_detail_user_display_name), key.userDisplayName ?: "-")

        // Discoverable badge
        val discoverableBadge = if (key.isDiscoverable) {
            createInlineBadge("Discoverable", semanticColor(R.color.security_verified))
        } else {
            createInlineBadge("Non-discoverable", semanticColor(R.color.security_neutral))
        }
        val badgeRow = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(4)
            }
            gravity = Gravity.END
        }
        badgeRow.addView(discoverableBadge)
        content.addView(badgeRow)

        // Sign count
        addPremiumDetailRow(content, getString(R.string.key_detail_sign_count), key.signCount.toString())

        contentLayout.addView(card)
    }

    /**
     * Builds the Sharing card for FIDO2 keys.
     */
    private fun buildSharingCard(key: KeyEntity) {
        val card = createPremiumCard(
            title = getString(R.string.sharing_settings_title),
            icon = "\uD83D\uDD17"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        // Current policy badge
        lifecycleScope.launch {
            val (badgeText, badgeColor) = when (key.sharingPolicy) {
                SharingPolicyType.PRIVATE -> Pair(
                    getString(R.string.sharing_badge_private),
                    semanticColor(R.color.security_neutral)
                )
                SharingPolicyType.ALL_PEERS -> Pair(
                    getString(R.string.sharing_badge_shared),
                    semanticColor(R.color.security_verified)
                )
                SharingPolicyType.SELECTED_PEERS -> {
                    val peerCount = withContext(Dispatchers.IO) {
                        keySharingPolicyDao.getAllowedPeersForKey(key.keyId).size
                    }
                    Pair(
                        getString(R.string.sharing_badge_selected, peerCount),
                        semanticColor(R.color.security_info)
                    )
                }
            }

            val policyRow = LinearLayout(this@KeyDetailActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = dpToPxInt(12)
                }
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }

            val labelView = TextView(this@KeyDetailActivity).apply {
                text = getString(R.string.key_detail_status)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
                setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            }
            policyRow.addView(labelView)

            policyRow.addView(createInlineBadge(badgeText, badgeColor))
            // Appended, not inserted at 0: createPremiumCard puts the card's
            // own icon and title at index 0, so inserting here pushed the
            // "Sharing" heading below its own badge — the only card that did.
            content.addView(policyRow)

            // Policy description
            val description = when (key.sharingPolicy) {
                SharingPolicyType.PRIVATE -> getString(R.string.sharing_policy_private_desc)
                SharingPolicyType.ALL_PEERS -> getString(R.string.sharing_policy_all_peers_desc)
                SharingPolicyType.SELECTED_PEERS -> {
                    val peerCount = withContext(Dispatchers.IO) {
                        keySharingPolicyDao.getAllowedPeersForKey(key.keyId).size
                    }
                    if (peerCount == 0) {
                        getString(R.string.sharing_no_devices_selected)
                    } else {
                        getString(R.string.sharing_selected_count_desc, peerCount)
                    }
                }
            }

            val descView = TextView(this@KeyDetailActivity).apply {
                text = description
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
                setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = dpToPxInt(16)
                }
            }
            content.addView(descView)
        }

        // Manage Sharing button
        val manageButton = createPremiumButton(
            text = getString(R.string.sharing_manage_button),
            isPrimary = false
        ) {
            KeySharingBottomSheet.show(supportFragmentManager, key.keyId)
        }
        content.addView(manageButton)

        contentLayout.addView(card)
    }

    /**
     * Builds the Attestation card.
     */
    private fun buildAttestationCard(key: KeyEntity) {
        // Symmetric and HMAC keys cannot be attested
        if (key.keyType == "secret" || key.keyType == "hmac") return

        val card = createPremiumCard(
            title = getString(R.string.key_section_attestation),
            icon = "\uD83D\uDD0D"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        // Description
        val descriptionText = if (key.source == "xkmsd") {
            getString(R.string.attest_description_remote)
        } else {
            getString(R.string.attest_description_local)
        }
        val descView = TextView(this).apply {
            text = descriptionText
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(16)
            }
        }
        content.addView(descView)

        // Result container
        attestationContentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val noAttestView = TextView(this).apply {
            text = getString(R.string.attest_no_attestation_yet)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(8)
                bottomMargin = dpToPxInt(16)
            }
        }
        attestationContentLayout?.addView(noAttestView)
        content.addView(attestationContentLayout)

        // Progress indicator
        attestProgress = ProgressBar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER
            }
            visibility = View.GONE
            isIndeterminate = true
        }
        content.addView(attestProgress)

        // Verify button
        val buttonText = if (key.source == "xkmsd") {
            getString(R.string.attest_button_remote)
        } else {
            getString(R.string.attest_button)
        }

        attestButton = createPremiumButton(
            text = buttonText,
            isPrimary = false
        ) {
            if (key.source == "xkmsd") {
                performRemoteAttestation(key)
            } else {
                performLocalAttestation(key)
            }
        }
        content.addView(attestButton)

        contentLayout.addView(card)
    }

    /**
     * Builds the Actions card.
     */
    private fun buildActionsCard(key: KeyEntity) {
        val card = createPremiumCard(
            title = getString(R.string.key_section_actions),
            icon = "\u2699\uFE0F"
        )
        val content = card.findViewWithTag<LinearLayout>("card_content")

        // Export Public Key button (only for asymmetric local keys)
        val isAsymmetric = key.keyType != "secret" && key.keyType != "hmac"
        if (isAsymmetric && key.source != "xkmsd") {
            val exportButton = createPremiumButton(
                text = getString(R.string.key_action_export_public_key),
                isPrimary = false
            ) {
                exportPublicKey(key)
            }
            content.addView(exportButton)
        }

        // Delete button or system key note
        if (key.isSystemKey) {
            val systemNote = TextView(this).apply {
                text = getString(R.string.key_system_explanation)
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
                setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            }
            content.addView(systemNote)
        } else {
            val deleteButton = createPremiumButton(
                text = getString(R.string.key_action_delete),
                isDanger = true
            ) {
                showDeleteBottomSheet(key)
            }
            content.addView(deleteButton)
        }

        contentLayout.addView(card)
    }

    // -------------------------------------------------------------------------
    // Premium UI Components
    // -------------------------------------------------------------------------

    /**
     * Creates a premium-styled card with icon and title.
     */
    private fun createPremiumCard(title: String, icon: String): MaterialCardView {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(12)
            }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(dpToPxInt(20), dpToPxInt(16), dpToPxInt(20), dpToPxInt(16))
            tag = "card_content"
        }

        // Header row with icon and title
        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(12)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val iconView = TextView(this).apply {
            text = icon
            textSize = 18f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = dpToPxInt(10)
            }
        }
        headerRow.addView(iconView)

        val titleView = TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
            letterSpacing = 0.02f
        }
        headerRow.addView(titleView)

        content.addView(headerRow)
        card.addView(content)
        return card
    }

    /**
     * Adds a premium detail row with optional monospace styling.
     */
    private fun addPremiumDetailRow(
        parent: LinearLayout,
        label: String,
        value: String,
        isMonospace: Boolean = false
    ) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val labelView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
        }
        row.addView(labelView)

        val valueView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            typeface = if (isMonospace) Typeface.MONOSPACE else Typeface.DEFAULT_BOLD
            gravity = Gravity.END
            maxLines = if (isMonospace) 1 else 2
            if (isMonospace) {
                textSize = 10f
            }
        }
        row.addView(valueView)

        parent.addView(row)
    }

    /**
     * Creates an inline badge view.
     */
    private fun createInlineBadge(text: String, color: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(Color.WHITE)
            setPadding(dpToPxInt(10), dpToPxInt(4), dpToPxInt(10), dpToPxInt(4))
            background = GradientDrawable().apply {
                setColor(color)
                cornerRadius = dpToPx(10f)
            }
        }
    }

    /**
     * Creates a premium-styled button.
     */
    private fun createPremiumButton(
        text: String,
        isPrimary: Boolean = true,
        isDanger: Boolean = false,
        onClick: () -> Unit
    ): MaterialButton {
        return MaterialButton(this).apply {
            this.text = text
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(8)
            }

            when {
                isDanger -> {
                    strokeColor = ColorStateList.valueOf(
                        resolveThemeColor(androidx.appcompat.R.attr.colorError)
                    )
                    strokeWidth = dpToPxInt(1)
                    setBackgroundColor(Color.TRANSPARENT)
                    setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorError))
                    rippleColor = ColorStateList.valueOf(
                        UIHelpers.applyAlpha(
                            resolveThemeColor(androidx.appcompat.R.attr.colorError),
                            0.12f
                        )
                    )
                }
                isPrimary -> {
                    setBackgroundColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
                    setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnPrimary))
                }
                else -> {
                    strokeColor = ColorStateList.valueOf(
                        resolveThemeColor(androidx.appcompat.R.attr.colorPrimary)
                    )
                    strokeWidth = dpToPxInt(1)
                    setBackgroundColor(Color.TRANSPARENT)
                    setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
                }
            }

            cornerRadius = dpToPxInt(12)
            setOnClickListener { onClick() }
        }
    }

    /**
     * Shows a premium delete confirmation bottom sheet.
     */
    private fun showDeleteBottomSheet(key: KeyEntity) {
        val bottomSheet = BottomSheetDialog(this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPxInt(24), dpToPxInt(24), dpToPxInt(24), dpToPxInt(32))
            setBackgroundColor(resolveThemeColor(com.google.android.material.R.attr.colorSurface))
        }

        // Warning icon
        val iconContainer = LinearLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPxInt(64), dpToPxInt(64)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(16)
            }
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(UIHelpers.applyAlpha(
                    resolveThemeColor(androidx.appcompat.R.attr.colorError),
                    0.15f
                ))
            }
        }

        val warningIcon = TextView(this).apply {
            text = "\u26A0\uFE0F"
            textSize = 28f
        }
        iconContainer.addView(warningIcon)
        content.addView(iconContainer)

        // Title
        val titleView = TextView(this).apply {
            text = getString(R.string.key_delete_title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(12)
            }
        }
        content.addView(titleView)

        // Message
        val message = if (key.source == "xkmsd") {
            getString(R.string.remote_key_delete_message, key.label)
        } else {
            getString(R.string.key_delete_message, key.label)
        }
        val messageView = TextView(this).apply {
            text = message
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(24)
            }
        }
        content.addView(messageView)

        // Buttons row
        val buttonsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val cancelButton = MaterialButton(this).apply {
            text = getString(R.string.button_cancel)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpToPxInt(8)
            }
            strokeColor = ColorStateList.valueOf(
                resolveThemeColor(com.google.android.material.R.attr.colorOutline)
            )
            strokeWidth = dpToPxInt(1)
            setBackgroundColor(Color.TRANSPARENT)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            cornerRadius = dpToPxInt(12)
            setOnClickListener { bottomSheet.dismiss() }
        }
        buttonsRow.addView(cancelButton)

        val deleteButton = MaterialButton(this).apply {
            text = getString(R.string.key_delete_confirm)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = dpToPxInt(8)
            }
            setBackgroundColor(resolveThemeColor(androidx.appcompat.R.attr.colorError))
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnError))
            cornerRadius = dpToPxInt(12)
            setOnClickListener {
                bottomSheet.dismiss()
                deleteKey(key)
            }
        }
        buttonsRow.addView(deleteButton)

        content.addView(buttonsRow)

        bottomSheet.setContentView(content)
        bottomSheet.show()
    }

    // -------------------------------------------------------------------------
    // Attestation Methods
    // -------------------------------------------------------------------------

    /**
     * Performs local Android Key Attestation.
     */
    private fun performLocalAttestation(key: KeyEntity) {
        attestButton?.isEnabled = false
        attestProgress?.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                val nonce = ByteArray(32)
                SecureRandom().nextBytes(nonce)

                val chain = withContext(Dispatchers.IO) {
                    keystoreManager.getKeyAttestationWithChallenge(key.keyId, nonce)
                }

                if (chain == null || chain.isEmpty()) {
                    showAttestationError(getString(R.string.attest_not_available))
                    return@launch
                }

                val x509Chain = chain.filterIsInstance<X509Certificate>()
                displayLocalAttestationResult(x509Chain, nonce)

            } catch (e: Exception) {
                showAttestationError(getString(R.string.attest_error, e.message ?: "Unknown error"))
            } finally {
                attestButton?.isEnabled = true
                attestProgress?.visibility = View.GONE
            }
        }
    }

    /**
     * Performs remote attestation for xkmsd keys.
     */
    private fun performRemoteAttestation(key: KeyEntity) {
        val bottomSheet = BottomSheetDialog(this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPxInt(24), dpToPxInt(24), dpToPxInt(24), dpToPxInt(32))
            setBackgroundColor(resolveThemeColor(com.google.android.material.R.attr.colorSurface))
        }

        val titleView = TextView(this).apply {
            text = getString(R.string.attest_title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurface))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(16)
            }
        }
        content.addView(titleView)

        val messageView = TextView(this).apply {
            text = "Remote attestation requires an active connection to the paired device.\n\n" +
                    "To attest this key:\n" +
                    "1. Ensure the device is running xkmsd\n" +
                    "2. Connect via BLE or USB\n" +
                    "3. The attestation will verify the key's hardware backing (${key.remoteBackend ?: "unknown"} backend)"
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(resolveThemeColor(com.google.android.material.R.attr.colorOnSurfaceVariant))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = dpToPxInt(24)
            }
        }
        content.addView(messageView)

        val okButton = MaterialButton(this).apply {
            text = getString(R.string.button_ok)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            cornerRadius = dpToPxInt(12)
            setOnClickListener { bottomSheet.dismiss() }
        }
        content.addView(okButton)

        bottomSheet.setContentView(content)
        bottomSheet.show()
    }

    /**
     * Displays parsed attestation result.
     */
    private fun displayLocalAttestationResult(chain: List<X509Certificate>, nonce: ByteArray) {
        val layout = attestationContentLayout ?: return
        layout.removeAllViews()

        val leafCert = chain.firstOrNull() ?: return
        val extensionInfo = parseAttestationExtension(leafCert)

        // Verified badge
        val verifiedBadge = createInlineBadge(
            getString(R.string.attest_verified),
            semanticColor(R.color.security_verified)
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(16)
            }
        }
        layout.addView(verifiedBadge)

        // Attestation Overview
        addAttestationSectionHeader(layout, "Attestation Overview")

        val securityLevel = extensionInfo?.securityLevel
            ?: if (keystoreManager.isStrongBoxAvailable()) "StrongBox" else "TEE"
        addPremiumDetailRow(layout, getString(R.string.attest_security_level), securityLevel)
        addPremiumDetailRow(
            layout,
            getString(R.string.attest_chain_length),
            getString(R.string.attest_chain_count, chain.size)
        )

        if (extensionInfo != null) {
            val nonceMatch = extensionInfo.challenge?.contentEquals(nonce) ?: false
            addPremiumDetailRow(
                layout,
                getString(R.string.attest_nonce_match),
                if (nonceMatch) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
            )

            addPremiumDetailRow(
                layout,
                getString(R.string.attest_version),
                extensionInfo.attestationVersion.toString()
            )
            addPremiumDetailRow(
                layout,
                getString(R.string.attest_keymaster_version),
                extensionInfo.keymasterVersion.toString()
            )
            addPremiumDetailRow(layout, "Keymaster Security Level", extensionInfo.keymasterSecurityLevel)

            // Key Properties
            addAttestationSectionHeader(layout, "Key Properties")

            if (extensionInfo.keySize > 0) {
                addPremiumDetailRow(layout, "Key Size", "${extensionInfo.keySize} bits")
            }
            if (extensionInfo.purposes.isNotEmpty()) {
                addPremiumDetailRow(layout, "Purposes", extensionInfo.purposes.joinToString(", "))
            }
            if (extensionInfo.origin != null) {
                addPremiumDetailRow(layout, "Origin", extensionInfo.origin)
            }
            if (extensionInfo.algorithm != null) {
                addPremiumDetailRow(layout, "Algorithm", extensionInfo.algorithm)
            }
            if (extensionInfo.digest != null) {
                addPremiumDetailRow(layout, "Digest", extensionInfo.digest)
            }
            if (extensionInfo.padding != null) {
                addPremiumDetailRow(layout, "Padding", extensionInfo.padding)
            }
            if (extensionInfo.ecCurve != null) {
                addPremiumDetailRow(layout, "EC Curve", extensionInfo.ecCurve)
            }
            if (extensionInfo.userAuthType != null) {
                addPremiumDetailRow(layout, "User Auth Type", extensionInfo.userAuthType)
            }
            if (extensionInfo.authTimeout != null) {
                addPremiumDetailRow(layout, "Auth Timeout", "${extensionInfo.authTimeout}s")
            }
            addPremiumDetailRow(
                layout,
                "No Auth Required",
                if (extensionInfo.noAuthRequired) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
            )
            addPremiumDetailRow(
                layout,
                "All Applications",
                if (extensionInfo.allApplications) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
            )
            if (extensionInfo.creationDateTime != null) {
                val dateFormat = SimpleDateFormat("MMM d, yyyy HH:mm:ss", Locale.getDefault())
                addPremiumDetailRow(layout, "Creation Date", dateFormat.format(Date(extensionInfo.creationDateTime)))
            }
            if (extensionInfo.rollbackResistant) {
                addPremiumDetailRow(layout, "Rollback Resistant", getString(R.string.key_detail_yes))
            }

            // Device State
            addAttestationSectionHeader(layout, "Device State")

            if (extensionInfo.deviceLocked != null) {
                addPremiumDetailRow(
                    layout,
                    "Device Locked",
                    if (extensionInfo.deviceLocked) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
                )
            }
            if (extensionInfo.verifiedBootState != null) {
                addPremiumDetailRow(layout, "Verified Boot State", extensionInfo.verifiedBootState)
            }
            if (extensionInfo.osVersion != null) {
                addPremiumDetailRow(layout, "OS Version", extensionInfo.osVersion)
            }
            if (extensionInfo.osPatchLevel != null) {
                addPremiumDetailRow(layout, "OS Patch Level", extensionInfo.osPatchLevel)
            }
            if (extensionInfo.vendorPatchLevel != null) {
                addPremiumDetailRow(layout, "Vendor Patch Level", extensionInfo.vendorPatchLevel)
            }
            if (extensionInfo.bootPatchLevel != null) {
                addPremiumDetailRow(layout, "Boot Patch Level", extensionInfo.bootPatchLevel)
            }
            if (extensionInfo.attestationApplicationId != null) {
                addPremiumDetailRow(layout, "Application ID", extensionInfo.attestationApplicationId, isMonospace = true)
            }
        }

        // Certificate Chain Details
        addAttestationSectionHeader(layout, "Certificate Chain")
        val dateFormat = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
        chain.forEachIndexed { index, cert ->
            val certLabel = when (index) {
                0 -> "Leaf (Attestation)"
                chain.size - 1 -> "Root"
                else -> "Intermediate #$index"
            }
            addPremiumDetailRow(layout, certLabel, cert.subjectX500Principal.name.let { dn ->
                Regex("CN=([^,]+)").find(dn)?.groupValues?.getOrNull(1) ?: dn
            })
            addPremiumDetailRow(layout, "  Valid", "${dateFormat.format(cert.notBefore)} - ${dateFormat.format(cert.notAfter)}")
        }
    }

    private fun addAttestationSectionHeader(parent: LinearLayout, title: String) {
        val header = TextView(this).apply {
            text = title
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
            letterSpacing = 0.05f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = dpToPxInt(16)
                bottomMargin = dpToPxInt(8)
            }
        }
        parent.addView(header)
    }

    /**
     * Shows an attestation error message.
     */
    private fun showAttestationError(message: String) {
        attestProgress?.visibility = View.GONE
        attestButton?.isEnabled = true

        val layout = attestationContentLayout ?: return
        layout.removeAllViews()

        val errorBadge = createInlineBadge(
            getString(R.string.attest_failed),
            resolveThemeColor(androidx.appcompat.R.attr.colorError)
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                bottomMargin = dpToPxInt(8)
            }
        }
        layout.addView(errorBadge)

        val errorView = TextView(this).apply {
            text = message
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(resolveThemeColor(androidx.appcompat.R.attr.colorError))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        layout.addView(errorView)
    }

    // -------------------------------------------------------------------------
    // Attestation Extension Parsing
    // -------------------------------------------------------------------------

    private data class AttestationExtensionInfo(
        val attestationVersion: Int,
        val securityLevel: String,
        val keymasterVersion: Int,
        val keymasterSecurityLevel: String,
        val challenge: ByteArray?,
        val keySize: Int,
        val purposes: List<String>,
        val deviceLocked: Boolean?,
        val verifiedBootState: String?,
        val algorithm: String?,
        val digest: String?,
        val padding: String?,
        val ecCurve: String?,
        val origin: String?,
        val userAuthType: String?,
        val authTimeout: Int?,
        val noAuthRequired: Boolean,
        val allApplications: Boolean,
        val rollbackResistant: Boolean,
        val creationDateTime: Long?,
        val osVersion: String?,
        val osPatchLevel: String?,
        val vendorPatchLevel: String?,
        val bootPatchLevel: String?,
        val attestationApplicationId: String?
    )

    private fun parseAttestationExtension(cert: X509Certificate): AttestationExtensionInfo? {
        val extensionBytes = cert.getExtensionValue(ATTESTATION_EXTENSION_OID) ?: return null

        return try {
            if (extensionBytes.size < 4) return null
            val innerOffset = if (extensionBytes[1].toInt() and 0x80 != 0) {
                2 + (extensionBytes[1].toInt() and 0x7F)
            } else {
                2
            }
            val innerBytes = extensionBytes.copyOfRange(innerOffset, extensionBytes.size)

            if (innerBytes.isEmpty() || innerBytes[0] != 0x30.toByte()) return null

            val seqContentOffset = derLengthOffset(innerBytes, 1)
            val seqContent = innerBytes.copyOfRange(seqContentOffset, innerBytes.size)

            var pos = 0

            val attestationVersion = derReadInteger(seqContent, pos)
            pos = derSkipElement(seqContent, pos)

            val attestSecurityLevelValue = derReadEnumerated(seqContent, pos)
            pos = derSkipElement(seqContent, pos)
            val securityLevel = securityLevelNames[attestSecurityLevelValue] ?: "Unknown ($attestSecurityLevelValue)"

            val keymasterVersion = derReadInteger(seqContent, pos)
            pos = derSkipElement(seqContent, pos)

            val kmSecurityLevelValue = derReadEnumerated(seqContent, pos)
            pos = derSkipElement(seqContent, pos)
            val keymasterSecurityLevel = securityLevelNames[kmSecurityLevelValue] ?: "Unknown ($kmSecurityLevelValue)"

            val challenge = derReadOctetString(seqContent, pos)
            pos = derSkipElement(seqContent, pos)

            pos = derSkipElement(seqContent, pos)
            pos = derSkipElement(seqContent, pos)

            val teeEnforcedInfo = if (pos < seqContent.size) {
                parseTeeEnforcedList(seqContent, pos)
            } else {
                null
            }

            AttestationExtensionInfo(
                attestationVersion = attestationVersion,
                securityLevel = securityLevel,
                keymasterVersion = keymasterVersion,
                keymasterSecurityLevel = keymasterSecurityLevel,
                challenge = challenge,
                keySize = teeEnforcedInfo?.keySize ?: 0,
                purposes = teeEnforcedInfo?.purposes ?: emptyList(),
                deviceLocked = teeEnforcedInfo?.deviceLocked,
                verifiedBootState = teeEnforcedInfo?.verifiedBootState,
                algorithm = teeEnforcedInfo?.algorithm,
                digest = teeEnforcedInfo?.digest,
                padding = teeEnforcedInfo?.padding,
                ecCurve = teeEnforcedInfo?.ecCurve,
                origin = teeEnforcedInfo?.origin,
                userAuthType = teeEnforcedInfo?.userAuthType,
                authTimeout = teeEnforcedInfo?.authTimeout,
                noAuthRequired = teeEnforcedInfo?.noAuthRequired ?: false,
                allApplications = teeEnforcedInfo?.allApplications ?: false,
                rollbackResistant = teeEnforcedInfo?.rollbackResistant ?: false,
                creationDateTime = teeEnforcedInfo?.creationDateTime,
                osVersion = teeEnforcedInfo?.osVersion,
                osPatchLevel = teeEnforcedInfo?.osPatchLevel,
                vendorPatchLevel = teeEnforcedInfo?.vendorPatchLevel,
                bootPatchLevel = teeEnforcedInfo?.bootPatchLevel,
                attestationApplicationId = teeEnforcedInfo?.attestationApplicationId
            )
        } catch (e: Exception) {
            null
        }
    }

    private data class TeeEnforcedInfo(
        val keySize: Int,
        val purposes: List<String>,
        val deviceLocked: Boolean?,
        val verifiedBootState: String?,
        val algorithm: String?,
        val digest: String?,
        val padding: String?,
        val ecCurve: String?,
        val origin: String?,
        val userAuthType: String?,
        val authTimeout: Int?,
        val noAuthRequired: Boolean,
        val allApplications: Boolean,
        val rollbackResistant: Boolean,
        val creationDateTime: Long?,
        val osVersion: String?,
        val osPatchLevel: String?,
        val vendorPatchLevel: String?,
        val bootPatchLevel: String?,
        val attestationApplicationId: String?
    )

    private fun parseTeeEnforcedList(data: ByteArray, startPos: Int): TeeEnforcedInfo? {
        if (startPos >= data.size || data[startPos] != 0x30.toByte()) return null

        val seqContentOffset = startPos + derLengthOffset(data, startPos + 1)
        val seqLength = derReadLength(data, startPos + 1)
        val seqEnd = seqContentOffset + seqLength

        var keySize = 0
        val purposes = mutableListOf<String>()
        var deviceLocked: Boolean? = null
        var verifiedBootState: String? = null
        var algorithm: String? = null
        var digest: String? = null
        var padding: String? = null
        var ecCurve: String? = null
        var origin: String? = null
        var userAuthType: String? = null
        var authTimeout: Int? = null
        var noAuthRequired = false
        var allApplications = false
        var rollbackResistant = false
        var creationDateTime: Long? = null
        var osVersion: String? = null
        var osPatchLevel: String? = null
        var vendorPatchLevel: String? = null
        var bootPatchLevel: String? = null
        var attestationApplicationId: String? = null

        val purposeNames = mapOf(
            0 to "Encrypt", 1 to "Decrypt", 2 to "Sign", 3 to "Verify",
            4 to "Derive Key", 5 to "Wrap Key"
        )

        val algorithmNames = mapOf(
            1 to "RSA", 3 to "EC", 32 to "AES", 33 to "3DES", 128 to "HMAC"
        )

        val digestNames = mapOf(
            0 to "None", 1 to "MD5", 2 to "SHA-1", 3 to "SHA-224",
            4 to "SHA-256", 5 to "SHA-384", 6 to "SHA-512"
        )

        val paddingNames = mapOf(
            1 to "None", 2 to "RSA-OAEP", 3 to "RSA-PSS", 4 to "RSA-PKCS1-1.5-Encrypt",
            5 to "RSA-PKCS1-1.5-Sign", 64 to "PKCS7"
        )

        val ecCurveNames = mapOf(
            0 to "P-224", 1 to "P-256", 2 to "P-384", 3 to "P-521", 4 to "Curve25519"
        )

        val originNames = mapOf(
            0 to "Generated", 1 to "Derived", 2 to "Imported", 3 to "Unknown",
            4 to "Securely Imported"
        )

        val userAuthTypeNames = mapOf(
            0 to "None", 1 to "Password", 2 to "Fingerprint", 3 to "Password+Fingerprint"
        )

        val bootStateNames = mapOf(
            0 to "Verified", 1 to "Self-Signed", 2 to "Unverified", 3 to "Failed"
        )

        var pos = seqContentOffset
        while (pos < seqEnd && pos < data.size) {
            val tag = data[pos].toInt() and 0xFF

            try {
                when {
                    // Tag [1] - purposes
                    tag == 0xA1 -> {
                        val contentOffset = pos + derLengthOffset(data, pos + 1)
                        val contentLength = derReadLength(data, pos + 1)
                        val contentEnd = contentOffset + contentLength

                        var setPos = contentOffset
                        if (setPos < contentEnd && data[setPos] == 0x31.toByte()) {
                            val setContentOffset = setPos + derLengthOffset(data, setPos + 1)
                            val setContentLength = derReadLength(data, setPos + 1)
                            val setContentEnd = setContentOffset + setContentLength
                            var intPos = setContentOffset
                            while (intPos < setContentEnd && intPos < data.size) {
                                val purposeVal = derReadInteger(data, intPos)
                                purposes.add(purposeNames[purposeVal] ?: "Unknown($purposeVal)")
                                intPos = derSkipElement(data, intPos)
                            }
                        }
                    }
                    // Tag [2] - algorithm
                    tag == 0xA2 -> {
                        val contentOffset = pos + derLengthOffset(data, pos + 1)
                        val algVal = derReadInteger(data, contentOffset)
                        algorithm = algorithmNames[algVal] ?: "Unknown($algVal)"
                    }
                    // Tag [3] - keySize
                    tag == 0xA3 -> {
                        val contentOffset = pos + derLengthOffset(data, pos + 1)
                        keySize = derReadInteger(data, contentOffset)
                    }
                    // Tag [5] - digest
                    tag == 0xA5 -> {
                        val contentOffset = pos + derLengthOffset(data, pos + 1)
                        val contentLength = derReadLength(data, pos + 1)
                        val contentEnd = contentOffset + contentLength
                        val digests = mutableListOf<String>()
                        if (contentOffset < contentEnd && data[contentOffset] == 0x31.toByte()) {
                            val setContentOffset = contentOffset + derLengthOffset(data, contentOffset + 1)
                            val setContentLength = derReadLength(data, contentOffset + 1)
                            val setContentEnd = setContentOffset + setContentLength
                            var intPos = setContentOffset
                            while (intPos < setContentEnd && intPos < data.size) {
                                val digestVal = derReadInteger(data, intPos)
                                digests.add(digestNames[digestVal] ?: "Unknown($digestVal)")
                                intPos = derSkipElement(data, intPos)
                            }
                        }
                        if (digests.isNotEmpty()) digest = digests.joinToString(", ")
                    }
                    // Tag [6] - padding
                    tag == 0xA6 -> {
                        val contentOffset = pos + derLengthOffset(data, pos + 1)
                        val contentLength = derReadLength(data, pos + 1)
                        val contentEnd = contentOffset + contentLength
                        val paddings = mutableListOf<String>()
                        if (contentOffset < contentEnd && data[contentOffset] == 0x31.toByte()) {
                            val setContentOffset = contentOffset + derLengthOffset(data, contentOffset + 1)
                            val setContentLength = derReadLength(data, contentOffset + 1)
                            val setContentEnd = setContentOffset + setContentLength
                            var intPos = setContentOffset
                            while (intPos < setContentEnd && intPos < data.size) {
                                val padVal = derReadInteger(data, intPos)
                                paddings.add(paddingNames[padVal] ?: "Unknown($padVal)")
                                intPos = derSkipElement(data, intPos)
                            }
                        }
                        if (paddings.isNotEmpty()) padding = paddings.joinToString(", ")
                    }
                    // Tag [10] - ecCurve
                    tag == 0xAA -> {
                        val contentOffset = pos + derLengthOffset(data, pos + 1)
                        val curveVal = derReadInteger(data, contentOffset)
                        ecCurve = ecCurveNames[curveVal] ?: "Unknown($curveVal)"
                    }
                    // Tag [200] - origin
                    tag == 0xBE && pos + 1 < data.size && (data[pos + 1].toInt() and 0xFF) == 0x02 -> {
                        // Context-specific tag [702] is multi-byte: BF 82 BE 02
                        // Actually origin is tag [702] = BF 85 3E
                        // Let's handle it below in the multi-byte section
                    }
                    // Tag [303] - noAuthRequired (primitive, context [303])
                    // Tag [503] - allApplications
                    // Tag [505] - creationDateTime
                    // Multi-byte context-specific tags
                    tag == 0xBF && pos + 1 < data.size -> {
                        val secondByte = data[pos + 1].toInt() and 0xFF
                        val thirdByte = if (pos + 2 < data.size) data[pos + 2].toInt() and 0xFF else 0

                        when {
                            // Tag [503] = BF 83 77 - noAuthRequired
                            secondByte == 0x83 && thirdByte == 0x77 -> {
                                noAuthRequired = true
                            }
                            // Tag [504] = BF 83 78 - userAuthType
                            secondByte == 0x83 && thirdByte == 0x78 -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val authVal = derReadInteger(data, contentOffset)
                                userAuthType = userAuthTypeNames[authVal] ?: "Type($authVal)"
                            }
                            // Tag [505] = BF 83 79 - authTimeout
                            secondByte == 0x83 && thirdByte == 0x79 -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                authTimeout = derReadInteger(data, contentOffset)
                            }
                            // Tag [600] = BF 84 58 - allApplications
                            secondByte == 0x84 && thirdByte == 0x58 -> {
                                allApplications = true
                            }
                            // Tag [701] = BF 85 3D - creationDateTime
                            secondByte == 0x85 && thirdByte == 0x3D -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                creationDateTime = derReadLong(data, contentOffset)
                            }
                            // Tag [702] = BF 85 3E - origin
                            secondByte == 0x85 && thirdByte == 0x3E -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val originVal = derReadInteger(data, contentOffset)
                                origin = originNames[originVal] ?: "Unknown($originVal)"
                            }
                            // Tag [704] = BF 85 40 - rootOfTrust
                            secondByte == 0x85 && thirdByte == 0x40 -> {
                                val tagEnd = pos + 3
                                val rotContentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val rotLength = derReadLength(data, tagEnd)
                                val rotEnd = rotContentOffset + rotLength

                                if (rotContentOffset < rotEnd && data[rotContentOffset] == 0x30.toByte()) {
                                    val seqInnerOffset = rotContentOffset + derLengthOffset(data, rotContentOffset + 1)
                                    var rPos = seqInnerOffset

                                    if (rPos < rotEnd) rPos = derSkipElement(data, rPos)

                                    if (rPos < rotEnd && data[rPos] == 0x01.toByte()) {
                                        val boolContentOffset = rPos + derLengthOffset(data, rPos + 1)
                                        deviceLocked = data[boolContentOffset] != 0.toByte()
                                        rPos = derSkipElement(data, rPos)
                                    }

                                    if (rPos < rotEnd && data[rPos] == 0x0A.toByte()) {
                                        val enumVal = derReadEnumerated(data, rPos)
                                        verifiedBootState = bootStateNames[enumVal] ?: "Unknown($enumVal)"
                                    }
                                }
                            }
                            // Tag [705] = BF 85 41 - osVersion
                            secondByte == 0x85 && thirdByte == 0x41 -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val versionInt = derReadInteger(data, contentOffset)
                                val major = versionInt / 10000
                                val minor = (versionInt % 10000) / 100
                                val sub = versionInt % 100
                                osVersion = "$major.$minor.$sub"
                            }
                            // Tag [706] = BF 85 42 - osPatchLevel
                            secondByte == 0x85 && thirdByte == 0x42 -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val patchInt = derReadInteger(data, contentOffset)
                                val year = patchInt / 100
                                val month = patchInt % 100
                                osPatchLevel = "$year-%02d".format(month)
                            }
                            // Tag [709] = BF 85 45 - attestationApplicationId
                            secondByte == 0x85 && thirdByte == 0x45 -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val appIdBytes = derReadOctetString(data, contentOffset)
                                attestationApplicationId = appIdBytes?.joinToString("") { "%02x".format(it) }
                            }
                            // Tag [718] = BF 85 4E - vendorPatchLevel
                            secondByte == 0x85 && thirdByte == 0x4E -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val patchInt = derReadInteger(data, contentOffset)
                                val year = patchInt / 100
                                val month = patchInt % 100
                                vendorPatchLevel = "$year-%02d".format(month)
                            }
                            // Tag [719] = BF 85 4F - bootPatchLevel
                            secondByte == 0x85 && thirdByte == 0x4F -> {
                                val tagEnd = pos + 3
                                val contentOffset = tagEnd + derLengthFieldSize(data, tagEnd)
                                val patchInt = derReadInteger(data, contentOffset)
                                val year = patchInt / 100
                                val month = patchInt % 100
                                bootPatchLevel = "$year-%02d".format(month)
                            }
                            // Tag [303] = BF 82 2F - rollbackResistant
                            secondByte == 0x82 && thirdByte == 0x2F -> {
                                rollbackResistant = true
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                // Skip unparseable elements
            }

            pos = derSkipElement(data, pos)
        }

        return TeeEnforcedInfo(
            keySize, purposes, deviceLocked, verifiedBootState,
            algorithm, digest, padding, ecCurve, origin,
            userAuthType, authTimeout, noAuthRequired, allApplications,
            rollbackResistant, creationDateTime, osVersion, osPatchLevel,
            vendorPatchLevel, bootPatchLevel, attestationApplicationId
        )
    }

    // -------------------------------------------------------------------------
    // DER Parsing Helpers
    // -------------------------------------------------------------------------

    private fun derReadInteger(data: ByteArray, pos: Int): Int {
        if (pos >= data.size || data[pos] != 0x02.toByte()) return 0
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        var value = 0
        for (i in 0 until minOf(length, 4)) {
            value = (value shl 8) or (data[contentOffset + i].toInt() and 0xFF)
        }
        return value
    }

    private fun derReadLong(data: ByteArray, pos: Int): Long {
        if (pos >= data.size || data[pos] != 0x02.toByte()) return 0L
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        var value = 0L
        for (i in 0 until minOf(length, 8)) {
            value = (value shl 8) or (data[contentOffset + i].toLong() and 0xFF)
        }
        return value
    }

    private fun derReadEnumerated(data: ByteArray, pos: Int): Int {
        if (pos >= data.size || data[pos] != 0x0A.toByte()) return -1
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        var value = 0
        for (i in 0 until minOf(length, 4)) {
            value = (value shl 8) or (data[contentOffset + i].toInt() and 0xFF)
        }
        return value
    }

    private fun derReadOctetString(data: ByteArray, pos: Int): ByteArray? {
        if (pos >= data.size || data[pos] != 0x04.toByte()) return null
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        if (contentOffset + length > data.size) return null
        return data.copyOfRange(contentOffset, contentOffset + length)
    }

    private fun derReadLength(data: ByteArray, pos: Int): Int {
        if (pos >= data.size) return 0
        val firstByte = data[pos].toInt() and 0xFF
        if (firstByte and 0x80 == 0) return firstByte
        val numBytes = firstByte and 0x7F
        var length = 0
        for (i in 1..numBytes) {
            if (pos + i >= data.size) return 0
            length = (length shl 8) or (data[pos + i].toInt() and 0xFF)
        }
        return length
    }

    /**
     * Size in bytes of the DER length field beginning at [pos].
     *
     * Tag bytes are the caller's business, which is what makes this usable for
     * both the one-byte `0xAn` tags and the three-byte `BF xx yy` ones.
     */
    private fun derLengthFieldSize(data: ByteArray, pos: Int): Int {
        if (pos >= data.size) return 1
        val first = data[pos].toInt() and 0xFF
        return if (first and 0x80 == 0) 1 else 1 + (first and 0x7F)
    }

    /**
     * Offset from a ONE-BYTE tag to its content: the tag byte plus the length
     * field. Callers with a multi-byte tag must use [derLengthFieldSize] and add
     * their own tag width — passing a three-byte tag here counts a tag byte
     * twice and reads the content one byte late.
     */
    private fun derLengthOffset(data: ByteArray, pos: Int): Int =
        1 + derLengthFieldSize(data, pos)

    private fun derSkipElement(data: ByteArray, pos: Int): Int {
        if (pos >= data.size) return data.size
        val tag = data[pos].toInt() and 0xFF

        var tagEnd = pos + 1
        if (tag and 0x1F == 0x1F) {
            while (tagEnd < data.size && data[tagEnd].toInt() and 0x80 != 0) {
                tagEnd++
            }
            tagEnd++
        }

        if (tagEnd >= data.size) return data.size
        val length = derReadLength(data, tagEnd)
        val lengthBytes = if (data[tagEnd].toInt() and 0x80 == 0) 1 else 1 + (data[tagEnd].toInt() and 0x7F)
        return tagEnd + lengthBytes + length
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    /**
     * Exports the public key in PEM format to clipboard.
     */
    private fun exportPublicKey(key: KeyEntity) {
        val pem = keystoreManager.getPublicKeyPEM(key.keyId)

        if (pem != null) {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Public Key", pem))
            Snackbar.make(coordinatorLayout, getString(R.string.key_public_key_copied), Snackbar.LENGTH_SHORT).show()
        } else {
            Snackbar.make(coordinatorLayout, getString(R.string.key_public_key_unavailable), Snackbar.LENGTH_SHORT).show()
        }
    }

    /**
     * Deletes the key from Keystore and database.
     */
    private fun deleteKey(key: KeyEntity) {
        lifecycleScope.launch {
            keyDao.deleteKeyAndMaterial(key.keyId) {
                if (key.source != "xkmsd") {
                    keystoreManager.resolveKeystoreAlias(key.keyId)?.let { keystoreManager.deleteByAlias(it) }
                }
            }
            finish()
        }
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
    // Display Helpers
    // -------------------------------------------------------------------------

    private fun getKeyTypeDisplayName(keyType: String): String = when (keyType) {
        "fido2" -> "FIDO2"
        "tls" -> "TLS"
        "ssh" -> "SSH"
        "signing" -> getString(R.string.key_filter_signing)
        "encryption" -> getString(R.string.key_filter_encryption)
        "secret" -> getString(R.string.key_filter_secret)
        "hmac" -> "HMAC"
        "ca" -> getString(R.string.key_filter_ca)
        "attestation" -> getString(R.string.key_filter_attestation)
        else -> keyType.replaceFirstChar { it.uppercase() }
    }

    private fun getSourceDisplayName(source: String): String = when (source) {
        "local" -> getString(R.string.key_source_local)
        "remote_ble" -> getString(R.string.key_source_remote_ble)
        "remote_usb" -> getString(R.string.key_source_remote_usb)
        "xkmsd" -> getString(R.string.key_source_xkmsd)
        else -> source.replaceFirstChar { it.uppercase() }
    }

    // -------------------------------------------------------------------------
    // Utility Helpers
    // -------------------------------------------------------------------------

    private fun resolveThemeColor(attr: Int): Int {
        val typedValue = TypedValue()
        theme.resolveAttribute(attr, typedValue, true)
        return ContextCompat.getColor(this, typedValue.resourceId)
    }

    private fun resolveActionBarSize(): Int {
        val typedValue = TypedValue()
        theme.resolveAttribute(android.R.attr.actionBarSize, typedValue, true)
        return TypedValue.complexToDimensionPixelSize(typedValue.data, resources.displayMetrics)
    }

    private fun dpToPx(dp: Float): Float {
        return TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, dp, resources.displayMetrics)
    }

    /**
     * Resolves a semantic state colour.
     *
     * State — verified, warning, neutral — must read the same on every screen
     * regardless of what kind of key is being shown, so these never come from
     * [CategoryPalette]. Category answers "what is this"; semantic answers
     * "is it healthy", and letting one borrow the other's colours makes both
     * unreadable.
     */
    @ColorInt
    private fun semanticColor(@ColorRes res: Int): Int = ContextCompat.getColor(this, res)

    private fun dpToPxInt(dp: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            resources.displayMetrics
        ).toInt()
    }
}
