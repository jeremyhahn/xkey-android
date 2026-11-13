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
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.VisibleForTesting
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.automatethethings.xkey.R
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity for managing PIV (Personal Identity Verification) smart card key slots.
 *
 * Displays all 25 PIV slots defined by NIST SP 800-73-4 in a scrollable card layout.
 * Primary slots (9A, 9C, 9D, 9E, F9) are shown prominently, while retired key history
 * slots (82-95) are grouped in a collapsible section.
 *
 * Features:
 * - Gradient toolbar with slot summary
 * - Hero summary card showing populated slot count and type badges
 * - Per-slot cards with key status, algorithm badges, and certificate expiry indicators
 * - Key generation dialog supporting ES256, ES384, and RS2048 algorithms
 * - Reactive UI updates via Room Flow observation
 *
 * Follows the programmatic UI pattern established by [OathActivity].
 */
class PivActivity : AppCompatActivity() {

    companion object {
        /** Number of days before expiry to show the expiring-soon warning. */
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
    private lateinit var summaryCard: MaterialCardView
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var badgeContainer: LinearLayout
    private lateinit var slotsContainer: LinearLayout
    private lateinit var retiredSlotsContainer: LinearLayout
    private lateinit var retiredToggleText: TextView
    private lateinit var emptyStateContainer: LinearLayout

    private var retiredSlotsExpanded = false

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val db = XKeyDatabase.getInstance(this)
        pivKeyManager = PivKeyManager(db.pivSlotDao())

        buildUI()
        setContentView(rootLayout)
        observeSlots()
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

    private fun buildUI() {
        rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            setBackgroundColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
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

        buildPremiumToolbar(mainContent)

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
                0,
                0,
                0,
                UIHelpers.dpToPxInt(this@PivActivity, 16)
            )
        }

        buildSummaryHeroCard()
        buildEmptyState()
        buildPrimarySlotsSection()
        buildRetiredSlotsSection()

        scrollView.addView(contentLayout)
        mainContent.addView(scrollView)
        rootLayout.addView(mainContent)
    }

    private fun buildPremiumToolbar(parent: LinearLayout) {
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
                UIHelpers.resolveActionBarSize(this@PivActivity)
            )
            setBackgroundColor(Color.TRANSPARENT)
            title = getString(R.string.piv_title)
            setTitleTextColor(ContextCompat.getColor(this@PivActivity, R.color.on_primary))
            elevation = 0f
        }
        toolbarContent.addView(toolbar)

        val subtitle = TextView(this).apply {
            text = getString(R.string.piv_subtitle)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(UIHelpers.applyAlpha(
                ContextCompat.getColor(this@PivActivity, R.color.on_primary),
                0.85f
            ))
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                0,
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                UIHelpers.dpToPxInt(this@PivActivity, 16)
            )
        }
        toolbarContent.addView(subtitle)

        toolbarContainer.addView(toolbarContent)
        parent.addView(toolbarContainer)

        setSupportActionBar(toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            setDisplayShowHomeEnabled(true)
        }
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))
    }

    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@PivActivity, 16),
                    UIHelpers.dpToPxInt(this@PivActivity, 16),
                    UIHelpers.dpToPxInt(this@PivActivity, 16),
                    UIHelpers.dpToPxInt(this@PivActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@PivActivity, 100)
        }

        PremiumCardFactory.applyDiagonalGradient(
            summaryCard,
            ContextCompat.getColor(this, R.color.gradient_tertiary_start),
            ContextCompat.getColor(this, R.color.tertiary_variant)
        )

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 20)
            )
        }

        // Left section: icon + count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            gravity = Gravity.CENTER_VERTICAL
        }

        val vaultIcon = ImageView(this).apply {
            setImageResource(android.R.drawable.ic_lock_idle_lock)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.applyAlpha(
                    ContextCompat.getColor(this@PivActivity, R.color.on_primary),
                    0.3f
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PivActivity, 64),
                UIHelpers.dpToPxInt(this@PivActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@PivActivity, 16)
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
            setTextColor(ContextCompat.getColor(this@PivActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.piv_count_zero)
            textSize = 14f
            setTextColor(UIHelpers.applyAlpha(
                ContextCompat.getColor(this@PivActivity, R.color.on_primary),
                0.9f
            ))
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        countSection.addView(vaultIcon)
        countSection.addView(textSection)

        // Right section: slot type badges
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

    private fun buildEmptyState() {
        emptyStateContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            visibility = View.GONE
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 48),
                UIHelpers.dpToPxInt(this@PivActivity, 48),
                UIHelpers.dpToPxInt(this@PivActivity, 48),
                UIHelpers.dpToPxInt(this@PivActivity, 48)
            )
        }

        val emptyIcon = ImageView(this).apply {
            setImageResource(android.R.drawable.ic_lock_idle_lock)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@PivActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PivActivity, 96),
                UIHelpers.dpToPxInt(this@PivActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.piv_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivActivity, 8)
            }
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.piv_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        contentLayout.addView(emptyStateContainer)
    }

    private fun buildPrimarySlotsSection() {
        val sectionHeader = TextView(this).apply {
            text = getString(R.string.piv_section_primary)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            letterSpacing = 0.05f
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 8)
            )
        }
        contentLayout.addView(sectionHeader)

        slotsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        contentLayout.addView(slotsContainer)
    }

    private fun buildRetiredSlotsSection() {
        // Toggle header for retired slots
        val toggleContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.CENTER_VERTICAL
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                UIHelpers.dpToPxInt(this@PivActivity, 20),
                UIHelpers.dpToPxInt(this@PivActivity, 8)
            )
            isClickable = true
            isFocusable = true
            setOnClickListener { toggleRetiredSlots() }
        }

        retiredToggleText = TextView(this).apply {
            text = getString(R.string.piv_section_retired_toggle, 20)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            letterSpacing = 0.05f
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
        }
        toggleContainer.addView(retiredToggleText)

        val chevron = TextView(this).apply {
            text = "\u25BC"
            textSize = 12f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }
        toggleContainer.addView(chevron)
        contentLayout.addView(toggleContainer)

        retiredSlotsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            visibility = View.GONE
        }
        contentLayout.addView(retiredSlotsContainer)
    }

    private fun toggleRetiredSlots() {
        retiredSlotsExpanded = !retiredSlotsExpanded
        retiredSlotsContainer.visibility = if (retiredSlotsExpanded) View.VISIBLE else View.GONE
    }

    // -------------------------------------------------------------------------
    // Data Observation
    // -------------------------------------------------------------------------

    private fun observeSlots() {
        val db = XKeyDatabase.getInstance(this)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                db.pivSlotDao().observeAll().collectLatest { entities ->
                    updateSlotCards(entities)
                    updateSummaryCard(entities)
                }
            }
        }
    }

    private fun updateSummaryCard(entities: List<PivSlotEntity>) {
        val populatedCount = entities.count { it.hasKey }
        totalCountText.text = populatedCount.toString()
        totalLabelText.text = when (populatedCount) {
            0 -> getString(R.string.piv_count_zero)
            1 -> getString(R.string.piv_count_one)
            else -> getString(R.string.piv_count, populatedCount)
        }

        badgeContainer.removeAllViews()

        // Create badges for each populated primary slot
        val entityMap = entities.associateBy { it.slotId }
        PivSlot.entries.filter { it.isPrimarySlot }.forEach { slot ->
            val entity = entityMap[slot.hexId]
            if (entity?.hasKey == true) {
                badgeContainer.addView(createSummaryBadge(
                    "${slot.hexId} ${slot.label.substringBefore(" ").substringAfterLast(" ")}",
                    ContextCompat.getColor(this, R.color.on_primary)
                ))
            }
        }
    }

    private fun createSummaryBadge(text: String, bgColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(ContextCompat.getColor(this@PivActivity, R.color.on_primary))
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 10),
                UIHelpers.dpToPxInt(this@PivActivity, 4),
                UIHelpers.dpToPxInt(this@PivActivity, 10),
                UIHelpers.dpToPxInt(this@PivActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(bgColor, 0.3f),
                UIHelpers.dpToPx(this@PivActivity, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PivActivity, 4)
            }
        }
    }

    private fun updateSlotCards(entities: List<PivSlotEntity>) {
        val entityMap = entities.associateBy { it.slotId }
        val hasAnyKey = entities.any { it.hasKey }

        // Show or hide empty state
        emptyStateContainer.visibility = if (hasAnyKey) View.GONE else View.VISIBLE

        // Rebuild primary slot cards
        slotsContainer.removeAllViews()
        PivSlot.entries.filter { it.isPrimarySlot }.forEach { slot ->
            slotsContainer.addView(buildSlotCard(slot, entityMap[slot.hexId]))
        }

        // Rebuild retired slot cards
        retiredSlotsContainer.removeAllViews()
        PivSlot.entries.filter { !it.isPrimarySlot }.forEach { slot ->
            retiredSlotsContainer.addView(buildSlotCard(slot, entityMap[slot.hexId]))
        }
    }

    // -------------------------------------------------------------------------
    // Slot Card Builder
    // -------------------------------------------------------------------------

    private fun buildSlotCard(slot: PivSlot, entity: PivSlotEntity?): MaterialCardView {
        val card = PremiumCardFactory.createElevatedCard(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@PivActivity, 16),
                    UIHelpers.dpToPxInt(this@PivActivity, 4),
                    UIHelpers.dpToPxInt(this@PivActivity, 16),
                    UIHelpers.dpToPxInt(this@PivActivity, 4)
                )
            }
        }

        val hasKey = entity?.hasKey == true

        val cardContent = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                UIHelpers.dpToPxInt(this@PivActivity, 16),
                UIHelpers.dpToPxInt(this@PivActivity, 16)
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        // Slot ID badge
        val slotBadge = createSlotIdBadge(slot.hexId, hasKey)
        cardContent.addView(slotBadge)

        // Slot info section
        val infoSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            ).apply {
                marginStart = UIHelpers.dpToPxInt(this@PivActivity, 12)
            }
        }

        // Slot label
        val labelText = TextView(this).apply {
            text = slot.label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
        }
        infoSection.addView(labelText)

        // Slot description
        val descText = TextView(this).apply {
            text = slot.description
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PivActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }
        infoSection.addView(descText)

        // If key is present, show algorithm badge and date
        if (hasKey && entity != null) {
            val metadataRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(this@PivActivity, 6)
                }
                gravity = Gravity.CENTER_VERTICAL
            }

            // Algorithm badge
            entity.algorithm?.let { algoName ->
                val algoBadge = createAlgorithmBadge(algoName)
                metadataRow.addView(algoBadge)
            }

            // Created date
            val dateFormat = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
            val createdText = TextView(this).apply {
                text = getString(R.string.piv_slot_created, dateFormat.format(Date(entity.createdAt)))
                textSize = 11f
                setTextColor(UIHelpers.resolveThemeColor(
                    this@PivActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    marginStart = UIHelpers.dpToPxInt(this@PivActivity, 8)
                }
            }
            metadataRow.addView(createdText)

            infoSection.addView(metadataRow)

            // Certificate info row if certificate is present
            if (entity.certificateDer != null) {
                val certInfoRow = buildCertificateInfoRow(entity.certificateDer)
                if (certInfoRow != null) {
                    infoSection.addView(certInfoRow)
                }
            }
        }

        cardContent.addView(infoSection)

        // Action button on the right
        val actionButton = MaterialButton(
            this,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                UIHelpers.dpToPxInt(this@PivActivity, 36)
            )
            textSize = 12f
            insetTop = 0
            insetBottom = 0
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 12),
                0,
                UIHelpers.dpToPxInt(this@PivActivity, 12),
                0
            )
        }

        if (hasKey) {
            actionButton.text = getString(R.string.piv_view_details)
            actionButton.setOnClickListener { navigateToDetail(slot) }
        } else {
            val accentColor = ContextCompat.getColor(this, R.color.gradient_tertiary_start)
            actionButton.text = getString(R.string.piv_generate_key)
            actionButton.setTextColor(accentColor)
            actionButton.strokeColor = ColorStateList.valueOf(accentColor)
            actionButton.setOnClickListener { showGenerateKeyDialog(slot) }
        }

        cardContent.addView(actionButton)
        card.addView(cardContent)

        if (hasKey) {
            card.setOnClickListener { navigateToDetail(slot) }
        }

        return card
    }

    private fun createSlotIdBadge(hexId: String, hasKey: Boolean): TextView {
        val goldColor = ContextCompat.getColor(this, R.color.secondary)
        val badgeBgColor = if (hasKey) goldColor else UIHelpers.resolveThemeColor(
            this,
            com.google.android.material.R.attr.colorSurfaceVariant
        )
        val badgeTextColor = if (hasKey) {
            ContextCompat.getColor(this, R.color.on_secondary)
        } else {
            UIHelpers.resolveThemeColor(
                this,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            )
        }

        return TextView(this).apply {
            text = hexId
            textSize = 16f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            setTextColor(badgeTextColor)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PivActivity, 48),
                UIHelpers.dpToPxInt(this@PivActivity, 48)
            )

            val bgDrawable = if (hasKey) {
                GradientDrawable(
                    GradientDrawable.Orientation.TL_BR,
                    intArrayOf(goldColor, UIHelpers.applyAlpha(goldColor, 0.8f))
                ).apply {
                    cornerRadius = UIHelpers.dpToPx(this@PivActivity, 12f)
                }
            } else {
                UIHelpers.createRoundedDrawable(
                    badgeBgColor,
                    UIHelpers.dpToPx(this@PivActivity, 12f)
                )
            }
            background = bgDrawable
        }
    }

    private fun createAlgorithmBadge(algorithmName: String): TextView {
        val accentColor = ContextCompat.getColor(this, R.color.gradient_tertiary_start)
        return TextView(this).apply {
            text = algorithmName
            textSize = 10f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            setTextColor(accentColor)
            setPadding(
                UIHelpers.dpToPxInt(this@PivActivity, 8),
                UIHelpers.dpToPxInt(this@PivActivity, 2),
                UIHelpers.dpToPxInt(this@PivActivity, 8),
                UIHelpers.dpToPxInt(this@PivActivity, 2)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(accentColor, 0.1f),
                UIHelpers.dpToPx(this@PivActivity, 8f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }

    private fun buildCertificateInfoRow(certDer: ByteArray): LinearLayout? {
        return try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(certDer.inputStream()) as X509Certificate

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

            LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(this@PivActivity, 4)
                }
                gravity = Gravity.CENTER_VERTICAL

                // Subject CN
                val subjectCn = extractCn(cert.subjectX500Principal.name)
                val subjectText = TextView(this@PivActivity).apply {
                    text = subjectCn
                    textSize = 11f
                    setTextColor(UIHelpers.resolveThemeColor(
                        this@PivActivity,
                        com.google.android.material.R.attr.colorOnSurfaceVariant
                    ))
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        1f
                    )
                    maxLines = 1
                }
                addView(subjectText)

                // Expiry badge
                val expiryBadge = TextView(this@PivActivity).apply {
                    text = statusText
                    textSize = 10f
                    setTextColor(ContextCompat.getColor(this@PivActivity, R.color.on_primary))
                    setPadding(
                        UIHelpers.dpToPxInt(this@PivActivity, 6),
                        UIHelpers.dpToPxInt(this@PivActivity, 2),
                        UIHelpers.dpToPxInt(this@PivActivity, 6),
                        UIHelpers.dpToPxInt(this@PivActivity, 2)
                    )
                    background = UIHelpers.createRoundedDrawable(
                        statusColor,
                        UIHelpers.dpToPx(this@PivActivity, 8f)
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    )
                }
                addView(expiryBadge)
            }
        } catch (_: Exception) {
            null
        }
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    private fun showGenerateKeyDialog(slot: PivSlot) {
        val algorithms = PivAlgorithm.entries.toTypedArray()
        val algorithmNames = algorithms.map { it.displayName }.toTypedArray()
        var selectedIndex = 0

        // AlertController only attaches a choice list when the message is
        // null, so setting both silently drops the list and pins the
        // selection to the first algorithm. The prompt therefore lives in the
        // title rather than as a message.
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.piv_generate_title, slot.hexId))
            .setSingleChoiceItems(algorithmNames, selectedIndex) { _, which ->
                selectedIndex = which
            }
            .setPositiveButton(getString(R.string.piv_generate_key)) { _, _ ->
                generateKey(slot, algorithms[selectedIndex])
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * The most recent key generation launched from the dialog, or null if none
     * was. Main thread only. Lets a test wait for the generation to finish
     * instead of sleeping; nothing in the app reads it.
     */
    @VisibleForTesting
    internal var generateJob: Job? = null
        private set

    private fun generateKey(slot: PivSlot, algorithm: PivAlgorithm) {
        generateJob = lifecycleScope.launch {
            try {
                pivKeyManager.generateKey(slot, algorithm)
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_generate_success, slot.hexId),
                    Snackbar.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                Snackbar.make(
                    rootLayout,
                    getString(R.string.piv_generate_error, e.message),
                    Snackbar.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun navigateToDetail(slot: PivSlot) {
        val intent = Intent(this, PivSlotDetailActivity::class.java).apply {
            putExtra(PivSlotDetailActivity.EXTRA_SLOT_ID, slot.hexId)
        }
        startActivity(intent)
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

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
}
