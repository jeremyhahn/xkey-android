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

import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.TextPaint
import android.util.TypedValue
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.AppCompatTextView
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/**
 * Details of one OATH credential: its parameters, usage, origin and the
 * current code with the time left, plus Copy. The secret is never shown:
 * [OathCredentialDetailViewModel] keeps it out of the screen state.
 *
 * Started from the OATH list's long-press Details with [EXTRA_OATH_ID];
 * closes itself when the credential is deleted while it is open.
 */
class OathCredentialDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_OATH_ID = "com.automatethethings.xkey.extra.OATH_ID"

        fun intent(context: Context, oathId: String): Intent =
            Intent(context, OathCredentialDetailActivity::class.java)
                .putExtra(EXTRA_OATH_ID, oathId)
    }

    private lateinit var repository: OathRepository
    private lateinit var clipboard: OathCodeClipboard

    private val viewModel: OathCredentialDetailViewModel by viewModels {
        val dao = XKeyDatabase.getInstance(this).oathCredentialDao()
        val secrets = OathSecretManager()
        OathCredentialDetailViewModel.factory(
            oathId = intent.getStringExtra(EXTRA_OATH_ID).orEmpty(),
            load = dao::getByOathId,
            secretOf = { entity -> secrets.decryptSecret(entity.secretEncrypted) }
        )
    }

    private lateinit var fieldsLayout: LinearLayout
    private lateinit var codeText: TextView
    private lateinit var timeLeftText: TextView
    private lateinit var hintText: TextView

    private val dateFormat: DateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.getStringExtra(EXTRA_OATH_ID).isNullOrEmpty()) {
            finish()
            return
        }
        repository = OathRepository(XKeyDatabase.getInstance(this).oathCredentialDao(), OathSecretManager())
        clipboard = OathCodeClipboard.create(this, repository)

        setContentView(buildUI())

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { viewModel.run() }
                viewModel.state.collect { render(it) }
            }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        android.R.id.home -> {
            onBackPressedDispatcher.onBackPressed()
            true
        }
        else -> super.onOptionsItemSelected(item)
    }

    private fun buildUI(): LinearLayout {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(UIHelpers.resolveThemeColor(this@OathCredentialDetailActivity, android.R.attr.colorBackground))
        }

        val toolbar = Toolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@OathCredentialDetailActivity)
            )
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(
                    ContextCompat.getColor(this@OathCredentialDetailActivity, R.color.gradient_primary_start),
                    ContextCompat.getColor(this@OathCredentialDetailActivity, R.color.gradient_primary_end)
                )
            )
            title = getString(R.string.oath_detail_title)
            setTitleTextColor(ContextCompat.getColor(this@OathCredentialDetailActivity, R.color.on_primary))
        }
        root.addView(toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.navigationIcon?.setTint(ContextCompat.getColor(this, R.color.on_primary))

        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = UIHelpers.dpToPxInt(this@OathCredentialDetailActivity, 12)
            setPadding(pad, pad, pad, pad)
        }
        scroll.addView(column)
        root.addView(scroll)

        // Code card: the code never wraps or ellipsizes; it shrinks to fit
        // when a narrow screen or a large font scale leaves too little room.
        val codeCard = PremiumCardFactory.createElevatedCard(this)
        val codeColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = UIHelpers.dpToPxInt(this@OathCredentialDetailActivity, 16)
            setPadding(pad, pad, pad, pad)
        }
        codeColumn.addView(label(getString(R.string.oath_detail_code)))
        codeText = FitWidthTextView(this).apply {
            keepWhole()
            textSize = 32f
            typeface = Typeface.MONOSPACE
            letterSpacing = 0.1f
            setTextColor(UIHelpers.resolveThemeColor(this@OathCredentialDetailActivity, androidx.appcompat.R.attr.colorPrimary))
            tag = "code"
        }
        codeColumn.addView(codeText)
        timeLeftText = TextView(this).apply {
            keepWhole()
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            tag = "timeLeft"
        }
        codeColumn.addView(timeLeftText)
        hintText = TextView(this).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            text = getString(R.string.oath_detail_hotp_hint)
        }
        codeColumn.addView(hintText)
        codeColumn.addView(MaterialButton(this).apply {
            text = getString(R.string.oath_detail_copy)
            tag = "copy"
            setOnClickListener { copyCode() }
        })
        codeCard.addView(codeColumn)
        column.addView(codeCard)

        val fieldsCard = PremiumCardFactory.createElevatedCard(this)
        fieldsLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = UIHelpers.dpToPxInt(this@OathCredentialDetailActivity, 16)
            setPadding(pad, pad, pad, 0)
        }
        fieldsCard.addView(fieldsLayout)
        column.addView(fieldsCard)
        return root
    }

    private fun render(state: OathCredentialDetailUiState) {
        when (state) {
            OathCredentialDetailUiState.Loading -> Unit
            OathCredentialDetailUiState.Gone -> finish()
            is OathCredentialDetailUiState.Shown -> show(state.details)
        }
    }

    private fun show(d: OathCredentialDetails) {
        codeText.text = OathAdapter.formatCode(d.code)
        if (d.secondsLeft != null) {
            timeLeftText.text = getString(R.string.oath_detail_time_left, d.secondsLeft)
            timeLeftText.visibility = android.view.View.VISIBLE
        } else {
            timeLeftText.visibility = android.view.View.GONE
        }
        hintText.visibility = if (d.counter != null) android.view.View.VISIBLE else android.view.View.GONE

        fieldsLayout.removeAllViews()
        d.issuer?.let { addRow(R.string.oath_detail_issuer, it) }
        addRow(R.string.oath_detail_account, d.accountName)
        addRow(R.string.oath_detail_type, d.type)
        addRow(R.string.oath_detail_algorithm, d.algorithm)
        addRow(R.string.oath_detail_digits, d.digits.toString())
        d.periodSeconds?.let { addRow(R.string.oath_detail_period, getString(R.string.oath_detail_period_value, it)) }
        d.counter?.let { addRow(R.string.oath_detail_counter, it.toString()) }
        addRow(R.string.oath_detail_created, dateFormat.format(Date(d.createdAt)))
        addRow(
            R.string.oath_detail_last_used,
            d.lastUsedAt?.let { dateFormat.format(Date(it)) } ?: getString(R.string.oath_detail_never_used)
        )
        addRow(R.string.oath_detail_use_count, getString(R.string.oath_detail_times_used, d.useCount))
        addRow(R.string.oath_detail_source, d.source.replaceFirstChar { it.uppercase() })
        d.remoteDeviceId?.let { addRow(R.string.oath_detail_remote_device, it) }
        addRow(R.string.oath_detail_security, getString(R.string.oath_detail_security_value))
    }

    private fun addRow(labelRes: Int, value: String) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, UIHelpers.dpToPxInt(this@OathCredentialDetailActivity, 12))
        }
        row.addView(label(getString(labelRes)))
        row.addView(TextView(this).apply {
            text = value
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(UIHelpers.resolveThemeColor(this@OathCredentialDetailActivity, com.google.android.material.R.attr.colorOnSurface))
        })
        fieldsLayout.addView(row)
    }

    private fun label(text: String) = TextView(this).apply {
        this.text = text
        setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelSmall)
        setTextColor(UIHelpers.resolveThemeColor(this@OathCredentialDetailActivity, com.google.android.material.R.attr.colorOnSurfaceVariant))
    }

    private fun copyCode() {
        lifecycleScope.launch {
            try {
                if (viewModel.copy(clipboard) != null) {
                    Toast.makeText(this@OathCredentialDetailActivity, R.string.oath_code_copied, Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this@OathCredentialDetailActivity, e.message ?: e.javaClass.simpleName, Toast.LENGTH_LONG).show()
            }
        }
    }
}

/**
 * A single-line text that scales its size down, never below what fits,
 * when the width it is measured at cannot hold it at its own size, so the
 * end of the code is never cut off. The size set before the first measure
 * is the size it returns to whenever there is room.
 */
internal class FitWidthTextView(context: Context) : AppCompatTextView(context) {

    private var baseTextSize = 0f

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        if (baseTextSize == 0f) baseTextSize = textSize
        val target = fittedSize(widthMeasureSpec)
        if (textSize != target) setTextSize(TypedValue.COMPLEX_UNIT_PX, target)
        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
    }

    private fun fittedSize(widthMeasureSpec: Int): Float {
        if (MeasureSpec.getMode(widthMeasureSpec) == MeasureSpec.UNSPECIFIED) return baseTextSize
        val room = MeasureSpec.getSize(widthMeasureSpec) - compoundPaddingLeft - compoundPaddingRight
        val measurePaint = TextPaint(paint).apply { textSize = baseTextSize }
        val needed = measurePaint.measureText(text.toString())
        if (room <= 0 || needed <= room) return baseTextSize
        return baseTextSize * room / needed * SHRINK_MARGIN
    }

    private companion object {
        /** Keeps a scaled-down code clear of rounding at the edge. */
        const val SHRINK_MARGIN = 0.98f
    }
}
