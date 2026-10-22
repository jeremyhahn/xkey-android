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

import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
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
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Activity showing detailed metadata for a single FIDO2 passkey.
 *
 * Displays site information, account details, credential properties,
 * security settings, usage statistics, and a delete action. All content
 * is built programmatically into card sections following the app's
 * premium card pattern with a gradient toolbar.
 */
class PasskeyDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_KEY_ID = "key_id"
    }

    private lateinit var rootLayout: FrameLayout
    private lateinit var contentLayout: LinearLayout
    private lateinit var keyDao: KeyDao
    private var currentKeyId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        keyDao = XKeyDatabase.getInstance(this).keyDao()

        buildUI()

        val keyId = intent.getStringExtra(EXTRA_KEY_ID) ?: run {
            finish()
            return
        }
        currentKeyId = keyId
        loadPasskeyDetails(keyId)
    }

    override fun onResume() {
        super.onResume()
        currentKeyId?.let { loadPasskeyDetails(it) }
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
                this@PasskeyDetailActivity,
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
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16)
            )
        }

        scrollView.addView(contentLayout)
        mainContent.addView(scrollView)
        rootLayout.addView(mainContent)

        setContentView(rootLayout)
    }

    private fun buildPremiumToolbar(parent: LinearLayout) {
        val toolbarContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
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

        val toolbarContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT
            )
        }

        // Toolbar
        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@PasskeyDetailActivity)
            )
            setBackgroundColor(android.graphics.Color.TRANSPARENT)
            setTitleTextColor(ContextCompat.getColor(context, R.color.on_primary))
            title = getString(R.string.passkey_detail_title)
        }
        toolbarContent.addView(toolbar)

        // Subtitle
        val subtitle = TextView(this).apply {
            text = getString(R.string.passkey_card_description)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(UIHelpers.applyAlpha(
                ContextCompat.getColor(this@PasskeyDetailActivity, R.color.on_primary),
                0.85f
            ))
            setPadding(
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16),
                0,
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16)
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

    // -------------------------------------------------------------------------
    // Data Loading
    // -------------------------------------------------------------------------

    private fun loadPasskeyDetails(keyId: String) {
        lifecycleScope.launch {
            val key = keyDao.getByKeyId(keyId) ?: run {
                finish()
                return@launch
            }
            contentLayout.removeAllViews()
            displayPasskeyDetails(key)
        }
    }

    private fun displayPasskeyDetails(key: KeyEntity) {
        buildSiteInfoCard(key)
        buildAccountCard(key)
        buildCredentialCard(key)
        buildSecurityCard(key)
        buildUsageCard(key)
        buildActionsCard(key)
    }

    // -------------------------------------------------------------------------
    // Card Builders
    // -------------------------------------------------------------------------

    private fun buildSiteInfoCard(key: KeyEntity) {
        val card = createSectionCard(getString(R.string.passkey_section_site))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addDetailRow(content, getString(R.string.passkey_rp_name), key.rpName ?: "-")
        addDetailRow(content, getString(R.string.passkey_rp_id), key.rpId ?: "-")

        contentLayout.addView(card)
    }

    private fun buildAccountCard(key: KeyEntity) {
        val card = createSectionCard(getString(R.string.passkey_section_account))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addDetailRow(content, getString(R.string.passkey_user_name), key.userName ?: "-")
        addDetailRow(content, getString(R.string.passkey_user_display_name), key.userDisplayName ?: "-")

        contentLayout.addView(card)
    }

    private fun buildCredentialCard(key: KeyEntity) {
        val card = createSectionCard(getString(R.string.passkey_section_credential))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addDetailRow(content, getString(R.string.passkey_type), getString(R.string.passkey_type_value))
        addDetailRow(content, getString(R.string.passkey_algorithm), key.algorithm)
        addDetailRow(content, getString(R.string.passkey_key_size), getString(R.string.passkey_key_size_value, key.keySizeBits))
        addDetailRow(
            content,
            getString(R.string.passkey_discoverable),
            if (key.isDiscoverable) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
        )
        addDetailRow(content, getString(R.string.passkey_sign_count), key.signCount.toString())

        contentLayout.addView(card)
    }

    private fun buildSecurityCard(key: KeyEntity) {
        val card = createSectionCard(getString(R.string.passkey_section_security))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        addDetailRow(
            content,
            getString(R.string.passkey_strongbox),
            if (key.strongBoxBacked) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
        )
        addDetailRow(
            content,
            getString(R.string.passkey_biometric),
            if (key.biometricRequired) getString(R.string.key_detail_yes) else getString(R.string.key_detail_no)
        )
        addDetailRow(content, getString(R.string.passkey_source), getSourceDisplayName(key.source))
        addDetailRow(content, getString(R.string.passkey_sharing), getSharingDisplayName(key.sharingPolicy))

        contentLayout.addView(card)
    }

    private fun buildUsageCard(key: KeyEntity) {
        val card = createSectionCard(getString(R.string.passkey_section_usage))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val dateFormat = SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault())

        addDetailRow(content, getString(R.string.passkey_created), dateFormat.format(Date(key.createdAt)))
        addDetailRow(
            content,
            getString(R.string.passkey_last_used),
            if (key.lastUsedAt > 0) dateFormat.format(Date(key.lastUsedAt))
            else getString(R.string.passkey_never_used)
        )
        addDetailRow(content, getString(R.string.passkey_use_count), getString(R.string.passkey_times_used, key.useCount.toInt()))

        contentLayout.addView(card)
    }

    private fun buildActionsCard(key: KeyEntity) {
        val card = createSectionCard(getString(R.string.passkey_section_actions))
        val content = card.findViewWithTag<LinearLayout>("card_content")

        val deleteButton = MaterialButton(
            this,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            text = getString(R.string.key_action_delete)
            setTextColor(getColor(android.R.color.holo_red_dark))
            strokeColor = android.content.res.ColorStateList.valueOf(getColor(android.R.color.holo_red_dark))
            setOnClickListener { showDeleteConfirmation(key) }
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
                bottomMargin = UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 12)
            }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 20),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 20),
                UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 16)
            )
            tag = "card_content"
        }

        val titleView = TextView(this).apply {
            text = title
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PasskeyDetailActivity,
                androidx.appcompat.R.attr.colorPrimary
            ))
            letterSpacing = 0.02f
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 12)
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
                bottomMargin = UIHelpers.dpToPxInt(this@PasskeyDetailActivity, 8)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val labelView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f)
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PasskeyDetailActivity,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
        }
        row.addView(labelView)

        val valueView = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f)
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                this@PasskeyDetailActivity,
                com.google.android.material.R.attr.colorOnSurface
            ))
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.END
        }
        row.addView(valueView)

        parent.addView(row)
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
                    finish()
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun getSourceDisplayName(source: String): String = when (source) {
        "local" -> getString(R.string.key_source_local)
        "remote_ble" -> getString(R.string.key_source_remote_ble)
        "remote_usb" -> getString(R.string.key_source_remote_usb)
        "xkmsd" -> getString(R.string.key_source_xkmsd)
        else -> source
    }

    private fun getSharingDisplayName(policy: SharingPolicyType): String = when (policy) {
        SharingPolicyType.PRIVATE -> getString(R.string.sharing_policy_private)
        SharingPolicyType.ALL_PEERS -> getString(R.string.sharing_policy_all_peers)
        SharingPolicyType.SELECTED_PEERS -> getString(R.string.sharing_policy_selected_peers)
    }
}
