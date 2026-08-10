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
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
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
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Premium activity for viewing and managing FIDO2 passkeys.
 *
 * Features a gradient toolbar, hero summary card with passkey count and
 * feature badges, premium card-based list items, swipe-to-delete, and
 * long-press context menu. Fully programmatic UI following the
 * KeyManagementActivity pattern.
 */
class PasskeysActivity : AppCompatActivity() {

    private lateinit var keyDao: KeyDao
    private lateinit var adapter: PasskeyAdapter

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateContainer: LinearLayout
    private lateinit var summaryCard: MaterialCardView
    private lateinit var totalCountText: TextView
    private lateinit var totalLabelText: TextView
    private lateinit var badgeContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        keyDao = XKeyDatabase.getInstance(this).keyDao()

        buildUI()
        setContentView(rootLayout)
        observePasskeys()
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
                this@PasskeysActivity,
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
        buildKeyList()
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
                UIHelpers.resolveActionBarSize(this@PasskeysActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            title = getString(R.string.passkeys_title)
            setTitleTextColor(ContextCompat.getColor(this@PasskeysActivity, R.color.on_primary))
            elevation = 0f
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.passkeys_card_description)
            setTextColor(ContextCompat.getColor(
                this@PasskeysActivity,
                R.color.on_primary
            ).let { UIHelpers.applyAlpha(it, 0.85f) })
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@PasskeysActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@PasskeysActivity, 16),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 12)
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
                    UIHelpers.dpToPxInt(this@PasskeysActivity, 16),
                    UIHelpers.dpToPxInt(this@PasskeysActivity, 16),
                    UIHelpers.dpToPxInt(this@PasskeysActivity, 16),
                    UIHelpers.dpToPxInt(this@PasskeysActivity, 8)
                )
            }
            minimumHeight = UIHelpers.dpToPxInt(this@PasskeysActivity, 100)
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
                UIHelpers.dpToPxInt(this@PasskeysActivity, 20),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 20),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 20),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 20)
            )
        }

        // Left section
        val countSection = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            gravity = Gravity.CENTER_VERTICAL
        }

        val vaultIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_fido2)
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this@PasskeysActivity, R.color.on_primary)
                    .let { UIHelpers.applyAlpha(it, 0.3f) }
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PasskeysActivity, 64),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 64)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(this@PasskeysActivity, 16)
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
            setTextColor(ContextCompat.getColor(this@PasskeysActivity, R.color.on_primary))
            typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
            includeFontPadding = false
        }

        totalLabelText = TextView(this).apply {
            text = getString(R.string.passkeys_title)
            textSize = 14f
            setTextColor(ContextCompat.getColor(this@PasskeysActivity, R.color.on_primary)
                .let { UIHelpers.applyAlpha(it, 0.9f) })
        }

        textSection.addView(totalCountText)
        textSection.addView(totalLabelText)
        countSection.addView(vaultIcon)
        countSection.addView(textSection)

        // Right section: badges
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

    private fun buildKeyList() {
        adapter = PasskeyAdapter(
            onItemClick = { key -> openPasskeyDetail(key) },
            onItemLongClick = { key ->
                showContextMenu(key)
                true
            }
        )

        recyclerView = RecyclerView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            layoutManager = LinearLayoutManager(this@PasskeysActivity)
            this.adapter = this@PasskeysActivity.adapter
            setPadding(
                UIHelpers.dpToPxInt(this@PasskeysActivity, 12),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 4),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 12),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 24)
            )
            clipToPadding = false
        }

        recyclerView.itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator().apply {
            addDuration = 200
            removeDuration = 200
            moveDuration = 200
            changeDuration = 200
        }

        setupSwipeToDelete()
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
                UIHelpers.dpToPxInt(this@PasskeysActivity, 48),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 48),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 48),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 48)
            )
        }

        val emptyIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_key_fido2)
            imageTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(
                    this@PasskeysActivity,
                    com.google.android.material.R.attr.colorOutlineVariant
                )
            )
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(this@PasskeysActivity, 96),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 96)
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PasskeysActivity, 24)
            }
        }

        val emptyTitle = TextView(this).apply {
            text = getString(R.string.passkeys_empty_title)
            textSize = 20f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PasskeysActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PasskeysActivity, 8)
            }
        }

        val emptyDescription = TextView(this).apply {
            text = getString(R.string.passkeys_empty_description)
            textSize = 14f
            setTextColor(UIHelpers.resolveThemeColor(
                this@PasskeysActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.CENTER
        }

        emptyStateContainer.addView(emptyIcon)
        emptyStateContainer.addView(emptyTitle)
        emptyStateContainer.addView(emptyDescription)
        contentLayout.addView(emptyStateContainer)
    }

    // -------------------------------------------------------------------------
    // Swipe to Delete
    // -------------------------------------------------------------------------

    private fun setupSwipeToDelete() {
        val swipeCallback = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.LEFT) {
            private val paint = Paint().apply {
                color = ContextCompat.getColor(this@PasskeysActivity, android.R.color.holo_red_dark)
            }
            private val textPaint = Paint().apply {
                color = android.graphics.Color.WHITE
                textSize = 40f
                isAntiAlias = true
                textAlign = Paint.Align.RIGHT
            }
            private val cornerRadius = 16f * resources.displayMetrics.density

            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ) = false

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.bindingAdapterPosition
                val key = adapter.currentList[position]
                adapter.notifyItemChanged(position)
                showDeleteConfirmation(key)
            }

            override fun onChildDraw(
                c: Canvas, recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                dX: Float, dY: Float, actionState: Int, isCurrentlyActive: Boolean
            ) {
                if (dX < 0) {
                    val itemView = viewHolder.itemView
                    val rect = RectF(
                        itemView.right + dX, itemView.top.toFloat(),
                        itemView.right.toFloat(), itemView.bottom.toFloat()
                    )
                    c.drawRoundRect(rect, cornerRadius, cornerRadius, paint)
                    val textY = itemView.top + (itemView.height / 2f) + (textPaint.textSize / 3f)
                    c.drawText(
                        getString(R.string.passkey_context_delete),
                        itemView.right - 48f * resources.displayMetrics.density,
                        textY, textPaint
                    )
                }
                super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive)
            }
        }
        ItemTouchHelper(swipeCallback).attachToRecyclerView(recyclerView)
    }

    // -------------------------------------------------------------------------
    // Data Observation
    // -------------------------------------------------------------------------

    private fun observePasskeys() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                keyDao.observeByType("fido2").collectLatest { keys ->
                    updateUI(keys)
                    updateSummaryCard(keys)
                }
            }
        }
    }

    private fun updateUI(keys: List<KeyEntity>) {
        if (keys.isEmpty()) {
            emptyStateContainer.visibility = View.VISIBLE
            recyclerView.visibility = View.GONE
        } else {
            emptyStateContainer.visibility = View.GONE
            recyclerView.visibility = View.VISIBLE
        }
        adapter.submitList(keys)
    }

    private fun updateSummaryCard(keys: List<KeyEntity>) {
        totalCountText.text = keys.size.toString()
        totalLabelText.text = if (keys.size == 1) {
            getString(R.string.passkeys_count_one)
        } else {
            getString(R.string.passkeys_count, keys.size)
        }

        badgeContainer.removeAllViews()

        val discoverableCount = keys.count { it.isDiscoverable }
        val biometricCount = keys.count { it.biometricRequired }

        badgeContainer.addView(createSummaryBadge(
            "$discoverableCount Discoverable",
            ContextCompat.getColor(this, R.color.primary_60)
        ))
        badgeContainer.addView(createSummaryBadge(
            "$biometricCount Biometric",
            ContextCompat.getColor(this, R.color.tertiary_60)
        ))
    }

    private fun createSummaryBadge(text: String, bgColor: Int): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            setTextColor(ContextCompat.getColor(this@PasskeysActivity, R.color.on_primary))
            setPadding(
                UIHelpers.dpToPxInt(this@PasskeysActivity, 10),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 4),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 10),
                UIHelpers.dpToPxInt(this@PasskeysActivity, 4)
            )
            background = UIHelpers.createRoundedDrawable(
                UIHelpers.applyAlpha(bgColor, 0.3f),
                UIHelpers.dpToPx(this@PasskeysActivity, 12f)
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PasskeysActivity, 4)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    private fun openPasskeyDetail(key: KeyEntity) {
        val intent = Intent(this, PasskeyDetailActivity::class.java).apply {
            putExtra(PasskeyDetailActivity.EXTRA_KEY_ID, key.keyId)
        }
        startActivity(intent)
    }

    private fun showContextMenu(key: KeyEntity) {
        val displayName = key.rpName ?: key.rpId ?: key.label

        MaterialAlertDialogBuilder(this)
            .setTitle(displayName)
            .setItems(
                arrayOf(
                    getString(R.string.passkey_context_view_details),
                    getString(R.string.passkey_context_delete)
                )
            ) { _, which ->
                when (which) {
                    0 -> openPasskeyDetail(key)
                    1 -> showDeleteConfirmation(key)
                }
            }
            .show()
    }

    private fun showDeleteConfirmation(key: KeyEntity) {
        val displayName = key.rpName ?: key.rpId ?: key.label

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.passkey_delete_title)
            .setMessage(getString(R.string.passkey_delete_message, displayName))
            .setPositiveButton(R.string.key_delete_confirm) { _, _ ->
                lifecycleScope.launch {
                    keyDao.deleteByKeyId(key.keyId)
                    Snackbar.make(
                        rootLayout,
                        R.string.passkey_deleted,
                        Snackbar.LENGTH_SHORT
                    ).show()
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }
}
