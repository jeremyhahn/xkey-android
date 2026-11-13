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
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.card.MaterialCardView
import com.google.android.material.datepicker.MaterialDatePicker
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * Premium Audit Log activity for viewing security event history.
 *
 * Provides a comprehensive view of all security-relevant operations performed by xKey,
 * with advanced filtering, search, and export capabilities.
 *
 * Features:
 * - Hero summary card with total count and filter status
 * - Search bar for finding entries by key label
 * - Filter chips for operation type, key type, and date range
 * - Premium cards for each audit entry with expandable details
 * - Export to JSON or CSV
 */
class AuditLogActivity : AppCompatActivity() {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        private const val CHIP_ANIMATION_DURATION = 200L
        private const val SEARCH_DEBOUNCE_MS = 300L
        private const val DATE_FORMAT_DISPLAY = "MMM dd, yyyy"
        private const val DATE_FORMAT_FULL = "MMM dd, yyyy HH:mm:ss"
        private const val EXPORT_FILE_NAME = "xkey_audit_log"
    }

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private val auditLogDao: AuditLogDao by lazy {
        XKeyDatabase.getInstance(this).auditLogDao()
    }

    // -------------------------------------------------------------------------
    // UI Components
    // -------------------------------------------------------------------------

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var searchInput: EditText
    private lateinit var filterScrollView: HorizontalScrollView
    private lateinit var operationChipContainer: LinearLayout
    private lateinit var keyTypeChipContainer: LinearLayout
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var adapter: AuditLogAdapter

    // Summary card views
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var filterSummaryText: TextView

    // Filter state
    private val operationChips = mutableMapOf<AuditOperationType?, View>()
    private val keyTypeChips = mutableMapOf<String?, View>()
    private var currentOperationFilter: AuditOperationType? = null
    private var currentKeyTypeFilter: String? = null
    private var currentSearchQuery: String = ""
    private var dateRangeStart: Long? = null
    private var dateRangeEnd: Long? = null

    private var allEntries: List<AuditLogEntity> = emptyList()
    private var searchJob: Job? = null

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUI()
        setContentView(rootLayout)
        observeAuditLogs()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.audit_log_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                onBackPressedDispatcher.onBackPressed()
                true
            }
            R.id.menu_export_json -> {
                exportToJson()
                true
            }
            R.id.menu_export_csv -> {
                exportToCsv()
                true
            }
            R.id.menu_clear_filters -> {
                clearAllFilters()
                true
            }
            R.id.menu_clear_all_logs -> {
                confirmClearAllLogs()
                true
            }
            R.id.menu_delete_older -> {
                confirmDeleteOlderLogs()
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
                this@AuditLogActivity,
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

        buildPremiumToolbar()
        buildSummaryHeroCard()
        buildSearchBar()
        buildFilterSection()
        buildAuditLogList()
        buildEmptyState()

        rootLayout.addView(contentLayout)
    }

    private fun buildPremiumToolbar() {
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
                UIHelpers.resolveActionBarSize(this@AuditLogActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.audit_log_title)
            setTitleTextColor(ContextCompat.getColor(this@AuditLogActivity, R.color.on_primary))
            elevation = 0f

            // The menu is installed through onCreateOptionsMenu below, not here.
            // setSupportActionBar wraps this toolbar in a ToolbarActionBar, which
            // replaces any menu-item click listener set beforehand and clears the
            // menu to repopulate it from the activity — so inflating here left
            // export, clear-filters and both delete actions unreachable.
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.audit_log_subtitle)
            setTextColor(ContextCompat.getColor(
                this@AuditLogActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 12)
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

    private fun buildSummaryHeroCard() {
        summaryCard = PremiumCardFactory.createHeroCard(this).apply {
            (layoutParams as LinearLayout.LayoutParams).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@AuditLogActivity, 100)
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
                UIHelpers.dpToPxInt(this@AuditLogActivity, 20),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 20),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 20),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 20)
            )
        }

        // Left section: Icon and count
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
            gravity = Gravity.CENTER_VERTICAL
        }

        val auditIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_audit_log)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@AuditLogActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 64),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@AuditLogActivity, 16)
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
            setTextColor(ContextCompat.getColor(this@AuditLogActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.audit_log_entries_label)
            textSize = 14f
            setTextColor(ContextCompat.getColor(this@AuditLogActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        filterSummaryText = TextView(this).apply {
            text = getString(R.string.audit_log_no_filters)
            textSize = 12f
            setTextColor(ContextCompat.getColor(this@AuditLogActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.7f) })
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@AuditLogActivity, 4)
            }
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        textSection.addView(filterSummaryText)
        countSection.addView(auditIcon)
        countSection.addView(textSection)

        cardContent.addView(countSection)
        summaryCard.addView(cardContent)
        contentLayout.addView(summaryCard)
    }

    private fun buildSearchBar() {
        val searchContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 8),
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                    UIHelpers.dpToPxInt(this@AuditLogActivity, 8)
                )
            }
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 12),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 12)
            )
            gravity = Gravity.CENTER_VERTICAL
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.resolveThemeColor(
                    this@AuditLogActivity,
                    com.google.android.material.R.attr.colorSurfaceContainerHigh
                ),
                UIHelpers.dpToPx(this@AuditLogActivity, 28f)
            )
        }

        val searchIcon = ImageView(this).apply {
            setImageResource(android.R.drawable.ic_menu_search)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@AuditLogActivity,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 24),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 24)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@AuditLogActivity, 12)
            }
        }

        searchInput = EditText(this).apply {
            hint = getString(R.string.audit_log_search_hint)
            setHintTextColor(UIHelpers.resolveThemeColor(
                this@AuditLogActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            setTextColor(UIHelpers.resolveThemeColor(
                this@AuditLogActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            textSize = 16f
            background = null
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
            )
            setSingleLine()
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    searchJob?.cancel()
                    searchJob = lifecycleScope.launch {
                        delay(SEARCH_DEBOUNCE_MS)
                        currentSearchQuery = s?.toString() ?: ""
                        applyFilters()
                    }
                }
            })
        }

        val dateRangeButton = ImageView(this).apply {
            setImageResource(R.drawable.ic_calendar)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@AuditLogActivity,
                    androidx.appcompat.R.attr.colorPrimary
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 24),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 24)
            ).apply {
                marginStart = UIHelpers.dpToPxInt(this@AuditLogActivity, 12)
            }
            setOnClickListener { showDateRangePicker() }
            contentDescription = getString(R.string.audit_log_date_range)
        }

        searchContainer.addView(searchIcon)
        searchContainer.addView(searchInput)
        searchContainer.addView(dateRangeButton)
        contentLayout.addView(searchContainer)
    }

    private fun buildFilterSection() {
        val filterLabel = TextView(this).apply {
            text = getString(R.string.audit_log_filter_operation)
            textSize = 12f
            setTextColor(UIHelpers.resolveThemeColor(
                this@AuditLogActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 8),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 4)
            )
        }
        contentLayout.addView(filterLabel)

        // Operation type filter chips
        filterScrollView = HorizontalScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            isHorizontalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            isHorizontalFadingEdgeEnabled = true
            setFadingEdgeLength(UIHelpers.dpToPxInt(this@AuditLogActivity, 32))
        }

        operationChipContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 4),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 4)
            )
        }

        val operationFilters = listOf<Pair<AuditOperationType?, String>>(
            null to getString(R.string.audit_log_filter_all)
        ) + AuditOperationLabels.filterTypes.map { it to getOperationTypeDisplayName(it) }

        operationFilters.forEachIndexed { index, (type, label) ->
            val chip = createFilterChip(label, index == 0)
            chip.setOnClickListener {
                selectOperationChip(type)
            }
            operationChips[type] = chip
            operationChipContainer.addView(chip)
        }

        filterScrollView.addView(operationChipContainer)
        contentLayout.addView(filterScrollView)

        // Key type filter label
        val keyTypeLabel = TextView(this).apply {
            text = getString(R.string.audit_log_filter_key_type)
            textSize = 12f
            setTextColor(UIHelpers.resolveThemeColor(
                this@AuditLogActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 8),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 4)
            )
        }
        contentLayout.addView(keyTypeLabel)

        // Key type filter chips
        val keyTypeScrollView = HorizontalScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            isHorizontalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            isHorizontalFadingEdgeEnabled = true
            setFadingEdgeLength(UIHelpers.dpToPxInt(this@AuditLogActivity, 32))
        }

        keyTypeChipContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 4),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 8)
            )
        }

        val keyTypeFilters = listOf(
            null to getString(R.string.key_filter_all),
            "fido2" to getString(R.string.key_filter_fido2),
            "signing" to getString(R.string.key_filter_signing),
            "encryption" to getString(R.string.key_filter_encryption),
            "secret" to getString(R.string.key_filter_secret)
        )

        keyTypeFilters.forEachIndexed { index, (type, label) ->
            val chip = createFilterChip(label, index == 0)
            chip.setOnClickListener {
                selectKeyTypeChip(type)
            }
            keyTypeChips[type] = chip
            keyTypeChipContainer.addView(chip)
        }

        keyTypeScrollView.addView(keyTypeChipContainer)
        contentLayout.addView(keyTypeScrollView)
    }

    private fun createFilterChip(text: String, isSelected: Boolean): View {
        val chip = TextView(this).apply {
            this.text = text
            textSize = 13f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 8),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 8)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@AuditLogActivity, 8)
            }
        }
        updateChipStyle(chip, isSelected)
        return chip
    }

    private fun updateChipStyle(chip: View, isSelected: Boolean) {
        val textView = chip as TextView

        if (isSelected) {
            val selectedColor = ContextCompat.getColor(this, R.color.secondary)
            val textColor = ContextCompat.getColor(this, R.color.on_secondary)

            textView.setTextColor(textColor)
            textView.background = UIHelpers.createPillDrawable(
                selectedColor,
                UIHelpers.dpToPx(this, 36f)
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
                UIHelpers.dpToPx(this, 18f),
                UIHelpers.dpToPxInt(this, 1),
                outlineColor
            )
        }
    }

    private fun selectOperationChip(type: AuditOperationType?) {
        operationChips[currentOperationFilter]?.let { updateChipStyle(it, false) }
        operationChips[type]?.let { updateChipStyle(it, true) }
        currentOperationFilter = type
        applyFilters()
    }

    private fun selectKeyTypeChip(type: String?) {
        keyTypeChips[currentKeyTypeFilter]?.let { updateChipStyle(it, false) }
        keyTypeChips[type]?.let { updateChipStyle(it, true) }
        currentKeyTypeFilter = type
        applyFilters()
    }

    private fun buildAuditLogList() {
        adapter = AuditLogAdapter()

        recyclerView = RecyclerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            layoutManager = LinearLayoutManager(this@AuditLogActivity)
            this.adapter = this@AuditLogActivity.adapter
            setPadding(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 12),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 4),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 12),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 16)
            )
            clipToPadding = false
        }

        recyclerView.itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator().apply {
            addDuration = 200
            removeDuration = 200
        }

        contentLayout.addView(recyclerView)
    }

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
                UIHelpers.dpToPxInt(this@AuditLogActivity, 48),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 48),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 48),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 48)
            )
        }

        val emptyIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_audit_log)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@AuditLogActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@AuditLogActivity, 96),
                UIHelpers.dpToPxInt(this@AuditLogActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@AuditLogActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.audit_log_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@AuditLogActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.audit_log_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@AuditLogActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(this@AuditLogActivity, 8)
            }
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        contentLayout.addView(emptyStateContainer)
    }

    // -------------------------------------------------------------------------
    // Data Management
    // -------------------------------------------------------------------------

    private fun observeAuditLogs() {
        lifecycleScope.launch {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                auditLogDao.observeAll().collectLatest { entries ->
                    allEntries = entries
                    applyFilters()
                }
            }
        }
    }

    private fun applyFilters() {
        var filtered = allEntries

        // Apply operation type filter
        if (currentOperationFilter != null) {
            filtered = filtered.filter { it.operationType == currentOperationFilter }
        }

        // Apply key type filter
        if (currentKeyTypeFilter != null) {
            filtered = filtered.filter { it.keyType == currentKeyTypeFilter }
        }

        // Apply search query
        if (currentSearchQuery.isNotBlank()) {
            filtered = filtered.filter {
                it.keyLabel?.contains(currentSearchQuery, ignoreCase = true) == true ||
                it.deviceName?.contains(currentSearchQuery, ignoreCase = true) == true
            }
        }

        // Apply date range filter
        if (dateRangeStart != null) {
            filtered = filtered.filter { it.timestamp >= dateRangeStart!! }
        }
        if (dateRangeEnd != null) {
            filtered = filtered.filter { it.timestamp <= dateRangeEnd!! }
        }

        adapter.submitList(filtered)
        updateSummaryCard(filtered.size)

        if (filtered.isEmpty()) {
            recyclerView.visibility = View.GONE
            emptyStateContainer.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            emptyStateContainer.visibility = View.GONE
        }
    }

    private fun updateSummaryCard(count: Int) {
        totalCountText.text = count.toString()
        totalLabelText.text = if (count == 1) {
            getString(R.string.audit_log_entry_label)
        } else {
            getString(R.string.audit_log_entries_label)
        }

        // Build filter summary
        val filterParts = mutableListOf<String>()
        if (currentOperationFilter != null) {
            filterParts.add(getOperationTypeDisplayName(currentOperationFilter!!))
        }
        if (currentKeyTypeFilter != null) {
            filterParts.add(currentKeyTypeFilter!!)
        }
        if (dateRangeStart != null || dateRangeEnd != null) {
            filterParts.add(getString(R.string.audit_log_date_filtered))
        }
        if (currentSearchQuery.isNotBlank()) {
            filterParts.add("\"$currentSearchQuery\"")
        }

        filterSummaryText.text = if (filterParts.isEmpty()) {
            getString(R.string.audit_log_no_filters)
        } else {
            getString(R.string.audit_log_filtered_by, filterParts.joinToString(", "))
        }
    }

    private fun clearAllFilters() {
        operationChips[currentOperationFilter]?.let { updateChipStyle(it, false) }
        operationChips[null]?.let { updateChipStyle(it, true) }
        currentOperationFilter = null

        keyTypeChips[currentKeyTypeFilter]?.let { updateChipStyle(it, false) }
        keyTypeChips[null]?.let { updateChipStyle(it, true) }
        currentKeyTypeFilter = null

        searchInput.setText("")
        currentSearchQuery = ""
        dateRangeStart = null
        dateRangeEnd = null

        applyFilters()
    }

    private fun confirmClearAllLogs() {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.audit_clear_all))
            .setMessage(getString(R.string.audit_clear_all_confirm))
            .setPositiveButton(getString(R.string.key_delete_confirm)) { _, _ ->
                lifecycleScope.launch {
                    auditLogDao.deleteAll()
                    Snackbar.make(rootLayout, getString(R.string.audit_logs_cleared), Snackbar.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    private fun confirmDeleteOlderLogs() {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.audit_delete_older))
            .setMessage(getString(R.string.audit_delete_older_confirm))
            .setPositiveButton(getString(R.string.key_delete_confirm)) { _, _ ->
                lifecycleScope.launch {
                    val thirtyDaysAgo = System.currentTimeMillis() - (30L * 24 * 60 * 60 * 1000)
                    val deleted = auditLogDao.deleteOlderThan(thirtyDaysAgo)
                    Snackbar.make(rootLayout, getString(R.string.audit_old_logs_deleted, deleted), Snackbar.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(getString(R.string.button_cancel), null)
            .show()
    }

    private fun showDateRangePicker() {
        val picker = MaterialDatePicker.Builder.dateRangePicker()
            .setTitleText(getString(R.string.audit_log_select_date_range))
            .build()

        picker.addOnPositiveButtonClickListener { selection ->
            dateRangeStart = selection.first
            dateRangeEnd = selection.second?.let { it + 24 * 60 * 60 * 1000 - 1 }
            applyFilters()
        }

        picker.show(supportFragmentManager, "date_picker")
    }

    // -------------------------------------------------------------------------
    // Export Functions
    // -------------------------------------------------------------------------

    private fun exportToJson() {
        lifecycleScope.launch {
            try {
                val entries = auditLogDao.getFiltered(
                    currentOperationFilter,
                    currentKeyTypeFilter,
                    null,
                    dateRangeStart,
                    dateRangeEnd
                )

                val jsonArray = org.json.JSONArray()
                entries.forEach { entry ->
                    val obj = JSONObject().apply {
                        put("id", entry.id)
                        put("timestamp", entry.timestamp)
                        put("operationType", entry.operationType.name)
                        put("keyId", entry.keyId)
                        put("keyLabel", entry.keyLabel)
                        put("keyType", entry.keyType)
                        put("deviceId", entry.deviceId)
                        put("deviceName", entry.deviceName)
                        put("success", entry.success)
                        put("errorMessage", entry.errorMessage)
                        put("details", entry.details)
                        put("durationMs", entry.durationMs)
                    }
                    jsonArray.put(obj)
                }

                val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val file = File(cacheDir, "${EXPORT_FILE_NAME}_$timestamp.json")
                file.writeText(jsonArray.toString(2))

                shareFile(file, "application/json")
            } catch (e: Exception) {
                Snackbar.make(rootLayout, getString(R.string.audit_log_export_failed), Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    private fun exportToCsv() {
        lifecycleScope.launch {
            try {
                val entries = auditLogDao.getFiltered(
                    currentOperationFilter,
                    currentKeyTypeFilter,
                    null,
                    dateRangeStart,
                    dateRangeEnd
                )

                val csv = StringBuilder()
                csv.appendLine("ID,Timestamp,Operation,Key ID,Key Label,Key Type,Device ID,Device Name,Success,Error,Details,Duration (ms)")

                val dateFormat = SimpleDateFormat(DATE_FORMAT_FULL, Locale.US)
                entries.forEach { entry ->
                    csv.appendLine(
                        listOf(
                            entry.id,
                            dateFormat.format(Date(entry.timestamp)),
                            entry.operationType.name,
                            entry.keyId ?: "",
                            "\"${entry.keyLabel?.replace("\"", "\"\"") ?: ""}\"",
                            entry.keyType ?: "",
                            entry.deviceId ?: "",
                            "\"${entry.deviceName?.replace("\"", "\"\"") ?: ""}\"",
                            entry.success,
                            "\"${entry.errorMessage?.replace("\"", "\"\"") ?: ""}\"",
                            "\"${entry.details?.replace("\"", "\"\"") ?: ""}\"",
                            entry.durationMs ?: ""
                        ).joinToString(",")
                    )
                }

                val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val file = File(cacheDir, "${EXPORT_FILE_NAME}_$timestamp.csv")
                file.writeText(csv.toString())

                shareFile(file, "text/csv")
            } catch (e: Exception) {
                Snackbar.make(rootLayout, getString(R.string.audit_log_export_failed), Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    private fun shareFile(file: File, mimeType: String) {
        val uri = FileProvider.getUriForFile(
            this,
            "$packageName.fileprovider",
            file
        )

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        startActivity(Intent.createChooser(shareIntent, getString(R.string.audit_log_export_title)))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun getOperationTypeDisplayName(type: AuditOperationType): String =
        getString(AuditOperationLabels.labelRes(type))

    private fun getOperationTypeColor(type: AuditOperationType): Pair<Int, Int> = when (type) {
        AuditOperationType.KEY_CREATED,
        AuditOperationType.FIDO2_REGISTRATION -> Pair(
            ContextCompat.getColor(this, R.color.security_verified),
            ContextCompat.getColor(this, R.color.on_primary)
        )
        AuditOperationType.KEY_DELETED,
        AuditOperationType.DEVICE_UNPAIRED -> Pair(
            ContextCompat.getColor(this, R.color.security_error),
            ContextCompat.getColor(this, R.color.on_primary)
        )
        AuditOperationType.SIGNING_REQUEST,
        AuditOperationType.ENCRYPTION_REQUEST,
        AuditOperationType.DECRYPTION_REQUEST,
        AuditOperationType.FIDO2_AUTHENTICATION -> Pair(
            ContextCompat.getColor(this, R.color.primary),
            ContextCompat.getColor(this, R.color.on_primary)
        )
        AuditOperationType.PAIRING_APPROVED,
        AuditOperationType.CONNECTION_ESTABLISHED -> Pair(
            ContextCompat.getColor(this, R.color.tertiary),
            ContextCompat.getColor(this, R.color.on_tertiary)
        )
        AuditOperationType.PAIRING_DENIED,
        AuditOperationType.POLICY_DENIED,
        AuditOperationType.BIOMETRIC_FAILURE -> Pair(
            ContextCompat.getColor(this, R.color.security_warning),
            ContextCompat.getColor(this, R.color.on_primary)
        )
        else -> Pair(
            ContextCompat.getColor(this, R.color.secondary),
            ContextCompat.getColor(this, R.color.on_secondary)
        )
    }

    // -------------------------------------------------------------------------
    // RecyclerView Adapter
    // -------------------------------------------------------------------------

    inner class AuditLogAdapter : ListAdapter<AuditLogEntity, AuditLogAdapter.ViewHolder>(AuditLogDiffCallback()) {

        private val expandedItems = mutableSetOf<Long>()

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            return ViewHolder(buildAuditLogCard(parent.context))
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(getItem(position))
        }

        private fun buildAuditLogCard(context: Context): MaterialCardView {
            val card = PremiumCardFactory.createElevatedCard(context).apply {
                (layoutParams as LinearLayout.LayoutParams).apply {
                    setMargins(
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 4),
                        UIHelpers.dpToPxInt(context, 4)
                    )
                }
            }

            val content = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                setPadding(
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 16),
                    UIHelpers.dpToPxInt(context, 12)
                )
            }

            // Header row
            val headerRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
                gravity = Gravity.CENTER_VERTICAL
            }

            val operationBadge = TextView(context).apply {
                textSize = 11f
                setPadding(
                    UIHelpers.dpToPxInt(context, 10),
                    UIHelpers.dpToPxInt(context, 4),
                    UIHelpers.dpToPxInt(context, 10),
                    UIHelpers.dpToPxInt(context, 4)
                )
                tag = "operationBadge"
            }

            val spacer = View(context).apply {
                layoutParams = LinearLayout.LayoutParams(0, 0, 1f)
            }

            val timestampText = TextView(context).apply {
                textSize = 12f
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                tag = "timestamp"
            }

            val statusIcon = ImageView(context).apply {
                layoutParams = LinearLayout.LayoutParams(
                    UIHelpers.dpToPxInt(context, 20),
                    UIHelpers.dpToPxInt(context, 20)
                ).apply {
                    marginStart = UIHelpers.dpToPxInt(context, 8)
                }
                tag = "statusIcon"
            }

            headerRow.addView(operationBadge)
            headerRow.addView(spacer)
            headerRow.addView(timestampText)
            headerRow.addView(statusIcon)

            // Main info
            val labelText = TextView(context).apply {
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurface
                ))
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 8)
                }
                tag = "label"
            }

            val deviceText = TextView(context).apply {
                textSize = 12f
                setTextColor(UIHelpers.resolveThemeColor(
                    context,
                    com.google.android.material.R.attr.colorOnSurfaceVariant
                ))
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 2)
                }
                tag = "device"
            }

            // Expandable details section
            val detailsContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                visibility = View.GONE
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    topMargin = UIHelpers.dpToPxInt(context, 12)
                }
                setPadding(
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 12),
                    UIHelpers.dpToPxInt(context, 8)
                )
                background = UIHelpers.createRoundedDrawable(
                    UIHelpers.resolveThemeColor(
                        context,
                        com.google.android.material.R.attr.colorSurfaceContainerHighest
                    ),
                    UIHelpers.dpToPx(context, 12f)
                )
                tag = "detailsContainer"
            }

            content.addView(headerRow)
            content.addView(labelText)
            content.addView(deviceText)
            content.addView(detailsContainer)
            card.addView(content)

            return card
        }

        inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

            private val operationBadge: TextView = itemView.findViewWithTag("operationBadge")
            private val timestampText: TextView = itemView.findViewWithTag("timestamp")
            private val statusIcon: ImageView = itemView.findViewWithTag("statusIcon")
            private val labelText: TextView = itemView.findViewWithTag("label")
            private val deviceText: TextView = itemView.findViewWithTag("device")
            private val detailsContainer: LinearLayout = itemView.findViewWithTag("detailsContainer")

            private val dateFormat = SimpleDateFormat(DATE_FORMAT_FULL, Locale.US)

            fun bind(entry: AuditLogEntity) {
                // Operation badge
                val (bgColor, textColor) = getOperationTypeColor(entry.operationType)
                operationBadge.text = getOperationTypeDisplayName(entry.operationType)
                operationBadge.setTextColor(textColor)
                operationBadge.background = UIHelpers.createRoundedDrawable(
                    bgColor,
                    UIHelpers.dpToPx(itemView.context, 10f)
                )

                // Timestamp
                timestampText.text = dateFormat.format(Date(entry.timestamp))

                // Status icon
                if (entry.success) {
                    statusIcon.setImageResource(R.drawable.ic_check_circle)
                    statusIcon.imageTintList = ColorStateList.valueOf(
                        ContextCompat.getColor(itemView.context, R.color.security_verified)
                    )
                } else {
                    statusIcon.setImageResource(R.drawable.ic_error)
                    statusIcon.imageTintList = ColorStateList.valueOf(
                        ContextCompat.getColor(itemView.context, R.color.security_error)
                    )
                }

                // Label
                labelText.text = when {
                    entry.keyLabel != null -> entry.keyLabel
                    entry.deviceName != null -> entry.deviceName
                    else -> entry.operationType.name.replace("_", " ")
                }

                // Device info
                val deviceInfo = buildString {
                    entry.keyType?.let { append("$it") }
                    entry.deviceName?.let {
                        if (isNotEmpty()) append(" | ")
                        append(it)
                    }
                    entry.durationMs?.let {
                        if (isNotEmpty()) append(" | ")
                        append("${it}ms")
                    }
                }
                deviceText.text = deviceInfo
                deviceText.visibility = if (deviceInfo.isNotBlank()) View.VISIBLE else View.GONE

                // Expand/collapse
                val isExpanded = expandedItems.contains(entry.id)
                detailsContainer.visibility = if (isExpanded) View.VISIBLE else View.GONE

                if (isExpanded) {
                    populateDetails(entry)
                }

                itemView.setOnClickListener {
                    if (expandedItems.contains(entry.id)) {
                        expandedItems.remove(entry.id)
                        detailsContainer.visibility = View.GONE
                    } else {
                        expandedItems.add(entry.id)
                        populateDetails(entry)
                        detailsContainer.visibility = View.VISIBLE
                    }
                }
            }

            private fun populateDetails(entry: AuditLogEntity) {
                detailsContainer.removeAllViews()

                entry.keyId?.let { addDetailRow(getString(R.string.key_detail_id), it) }
                entry.keyType?.let { addDetailRow(getString(R.string.key_detail_type), it) }
                entry.deviceId?.let { addDetailRow(getString(R.string.audit_log_device_id), it) }
                entry.errorMessage?.let {
                    addDetailRow(getString(R.string.audit_log_error), it, isError = true)
                }
                entry.durationMs?.let {
                    addDetailRow(getString(R.string.audit_log_duration), "${it}ms")
                }

                entry.details?.let { detailsJson ->
                    try {
                        val json = JSONObject(detailsJson)
                        json.keys().forEach { key ->
                            addDetailRow(key, json.optString(key))
                        }
                    } catch (e: Exception) {
                        addDetailRow(getString(R.string.audit_log_details), detailsJson)
                    }
                }
            }

            private fun addDetailRow(label: String, value: String, isError: Boolean = false) {
                val row = LinearLayout(itemView.context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply {
                        bottomMargin = UIHelpers.dpToPxInt(itemView.context, 4)
                    }
                }

                val labelView = TextView(itemView.context).apply {
                    text = "$label:"
                    textSize = 12f
                    setTextColor(UIHelpers.resolveThemeColor(
                        itemView.context,
                        com.google.android.material.R.attr.colorOnSurfaceVariant
                    ))
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply {
                        marginEnd = UIHelpers.dpToPxInt(itemView.context, 8)
                    }
                }

                val valueView = TextView(itemView.context).apply {
                    text = value
                    textSize = 12f
                    setTextColor(
                        if (isError) {
                            ContextCompat.getColor(itemView.context, R.color.security_error)
                        } else {
                            UIHelpers.resolveThemeColor(
                                itemView.context,
                                com.google.android.material.R.attr.colorOnSurface
                            )
                        }
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        1f
                    )
                    maxLines = 3
                    ellipsize = android.text.TextUtils.TruncateAt.END
                }

                row.addView(labelView)
                row.addView(valueView)
                detailsContainer.addView(row)
            }
        }
    }

    class AuditLogDiffCallback : DiffUtil.ItemCallback<AuditLogEntity>() {
        override fun areItemsTheSame(oldItem: AuditLogEntity, newItem: AuditLogEntity): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: AuditLogEntity, newItem: AuditLogEntity): Boolean {
            return oldItem == newItem
        }
    }
}
