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
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathCredentialWithCode
import kotlin.math.max

/**
 * RecyclerView adapter for displaying OATH credentials with premium card UI.
 *
 * Each item shows a gradient initial circle, issuer/account name, formatted
 * OTP code with monospace styling, countdown timer, and progress bar.
 * Uses programmatic card building with [PremiumCardFactory] for consistent styling.
 *
 * @param onItemClick Callback when a credential item is tapped.
 * @param onItemLongClick Callback when a credential item is long-pressed.
 */
class OathAdapter(
    private val onItemClick: (OathCredentialWithCode) -> Unit,
    private val onItemLongClick: (OathCredentialWithCode) -> Boolean
) : ListAdapter<OathCredentialWithCode, OathAdapter.ViewHolder>(OathDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(buildPremiumOathCard(parent.context))
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    private fun buildPremiumOathCard(context: Context): com.google.android.material.card.MaterialCardView {
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

        // The issuer and account are a small title line; the code has its
        // own line below and is never cut.
        val content = OathRowLayout(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 14),
                UIHelpers.dpToPxInt(context, 16),
                UIHelpers.dpToPxInt(context, 14)
            )
            leadingGap = UIHelpers.dpToPxInt(context, 12)
            stackGap = UIHelpers.dpToPxInt(context, 8)
            indicatorGap = UIHelpers.dpToPxInt(context, 12)
            progressGap = UIHelpers.dpToPxInt(context, 6)
        }

        // Gradient initial circle
        val initialContainer = FrameLayout(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                UIHelpers.dpToPxInt(context, 36),
                UIHelpers.dpToPxInt(context, 36)
            )
            tag = "initialContainer"
        }

        val initialText = TextView(context).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            gravity = Gravity.CENTER
            setTextColor(ContextCompat.getColor(context, R.color.on_primary))
            textSize = 16f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            tag = "initial"
        }
        initialContainer.addView(initialText)

        // Apply gradient background
        val gradientStart = ContextCompat.getColor(context, R.color.primary_40)
        val gradientEnd = ContextCompat.getColor(context, R.color.primary_60)
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(gradientStart, gradientEnd)
        ).apply {
            cornerRadius = UIHelpers.dpToPx(context, 18f)
        }
        initialContainer.background = gradient

        // Title: issuer and account in small text, one line each, ellipsized.
        val infoColumn = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val issuerText = TextView(context).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelLarge)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurface
            ))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            tag = "issuer"
        }
        infoColumn.addView(issuerText)

        val accountText = TextView(context).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            tag = "account"
        }
        infoColumn.addView(accountText)

        // Code line: the OTP code in large monospace, never cut.
        val codeText = TextView(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            keepWhole()
            textSize = 28f
            typeface = Typeface.MONOSPACE
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                androidx.appcompat.R.attr.colorPrimary
            ))
            letterSpacing = 0.1f
            tag = "code"
        }

        val countdownText = TextView(context).apply {
            keepWhole()
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            tag = "countdown"
        }

        val progressBar = ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.dpToPxInt(context, 4)
            )
            progressTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary)
            )
            progressBackgroundTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorSurfaceVariant)
            )
            tag = "progress"
        }

        content.setChildren(initialContainer, infoColumn, codeText, countdownText, progressBar)

        card.addView(content)
        return card
    }

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

        private val initialView: TextView = itemView.findViewWithTag("initial")
        private val issuerView: TextView = itemView.findViewWithTag("issuer")
        private val accountView: TextView = itemView.findViewWithTag("account")
        private val codeView: TextView = itemView.findViewWithTag("code")
        private val countdownView: TextView = itemView.findViewWithTag("countdown")
        private val progressView: ProgressBar = itemView.findViewWithTag("progress")

        fun bind(item: OathCredentialWithCode) {
            // Initial letter
            val initial = item.credential.issuer
                ?.firstOrNull()
                ?.uppercaseChar()
                ?.toString()
                ?: item.credential.accountName
                    .firstOrNull()
                    ?.uppercaseChar()
                    ?.toString()
                ?: "?"
            initialView.text = initial

            // Issuer text
            issuerView.text = item.credential.issuer ?: item.credential.accountName

            // Account name (hide if issuer is null to avoid duplication)
            accountView.text = item.credential.accountName
            accountView.visibility = if (item.credential.issuer != null) {
                View.VISIBLE
            } else {
                View.GONE
            }

            // OTP code
            codeView.text = formatCode(item.code)

            // Countdown
            countdownView.text = "${item.secondsRemaining}s"

            // Progress bar
            progressView.max = item.credential.periodSeconds
            progressView.progress = item.secondsRemaining

            // Click handlers
            itemView.setOnClickListener { onItemClick(item) }
            itemView.setOnLongClickListener { onItemLongClick(item) }
        }
    }

    class OathDiffCallback : DiffUtil.ItemCallback<OathCredentialWithCode>() {

        override fun areItemsTheSame(
            oldItem: OathCredentialWithCode,
            newItem: OathCredentialWithCode
        ): Boolean {
            return oldItem.credential.oathId == newItem.credential.oathId
        }

        override fun areContentsTheSame(
            oldItem: OathCredentialWithCode,
            newItem: OathCredentialWithCode
        ): Boolean {
            return oldItem.credential.oathId == newItem.credential.oathId &&
                oldItem.code == newItem.code &&
                oldItem.secondsRemaining == newItem.secondsRemaining
        }
    }

    companion object {
        /**
         * Format an OTP code with a space in the middle for readability.
         *
         * A 6-digit code "123456" becomes "123 456".
         * A 7-digit code "1234567" becomes "123 4567".
         * An 8-digit code "12345678" becomes "1234 5678".
         */
        fun formatCode(code: String): String {
            val midpoint = code.length / 2
            return "${code.substring(0, midpoint)} ${code.substring(midpoint)}"
        }
    }
}

/**
 * Keeps an OTP code (or its countdown) whole: one line, never ellipsized.
 * The row layout gives such a view its full width first.
 */
internal fun TextView.keepWhole() {
    isSingleLine = true
    ellipsize = null
}

/**
 * The OATH list row, one shape at every width and font scale:
 *
 * - a title line: the leading badge and the issuer/account column, which
 *   takes the rest of the width and ellipsizes;
 * - the code line below it: the code at its full natural width on one line,
 *   never ellipsized, with the [indicator] (the countdown) at the end of the
 *   same line, or under the code when both do not fit side by side;
 * - the [progress] bar across the row at the bottom.
 *
 * Only when the code alone is wider than the whole row is its text size
 * scaled down to keep it on one line. Children are added with
 * [setChildren]; the row mirrors for right-to-left layouts.
 */
internal class OathRowLayout(context: Context) : ViewGroup(context) {

    private lateinit var leading: View
    private lateinit var title: View
    private lateinit var code: TextView
    private lateinit var indicator: View
    private lateinit var progress: View

    /** Space after the leading badge. */
    var leadingGap: Int = 0

    /** Space between the title line and the code line. */
    var stackGap: Int = 0

    /** Least space between the code and the indicator beside it. */
    var indicatorGap: Int = 0

    /** Space above the progress bar. */
    var progressGap: Int = 0

    private var codeTextSize = 0f
    private var indicatorBelow = false

    fun setChildren(leading: View, title: View, code: TextView, indicator: View, progress: View) {
        removeAllViews()
        this.leading = leading
        this.title = title
        this.code = code
        this.indicator = indicator
        this.progress = progress
        codeTextSize = 0f
        addView(leading)
        addView(title)
        addView(code)
        addView(indicator)
        addView(progress)
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val inner = max(0, width - paddingLeft - paddingRight)
        val unspecified = MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED)

        if (codeTextSize == 0f) codeTextSize = code.textSize
        if (code.textSize != codeTextSize) code.setTextSize(TypedValue.COMPLEX_UNIT_PX, codeTextSize)

        leading.measure(fixedOrWrap(leading.layoutParams.width, inner), fixedOrWrap(leading.layoutParams.height, 0))
        val titleWidth = max(0, inner - leading.measuredWidth - leadingGap)
        title.measure(exactly(titleWidth), unspecified)
        val titleHeight = max(leading.measuredHeight, title.measuredHeight)

        code.measure(unspecified, unspecified)
        if (code.measuredWidth > inner && shrinkToFit(inner)) code.measure(unspecified, unspecified)
        code.measure(exactly(minOf(code.measuredWidth, inner)), unspecified)

        var codeLineHeight = code.measuredHeight
        indicatorBelow = false
        if (indicator.visibility != View.GONE) {
            indicator.measure(MeasureSpec.makeMeasureSpec(inner, MeasureSpec.AT_MOST), unspecified)
            indicatorBelow = code.measuredWidth + indicatorGap + indicator.measuredWidth > inner
            codeLineHeight = if (indicatorBelow) {
                code.measuredHeight + indicator.measuredHeight
            } else {
                max(code.measuredHeight, indicator.measuredHeight)
            }
        }

        var progressHeight = 0
        if (progress.visibility != View.GONE) {
            progress.measure(exactly(inner), fixedOrWrap(progress.layoutParams.height, 0))
            progressHeight = progressGap + progress.measuredHeight
        }

        val contentHeight = titleHeight + stackGap + codeLineHeight + progressHeight
        setMeasuredDimension(
            width,
            resolveSize(contentHeight + paddingTop + paddingBottom, heightMeasureSpec)
        )
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        val rowWidth = r - l
        val rtl = layoutDirection == View.LAYOUT_DIRECTION_RTL
        fun place(child: View, x: Int, y: Int) {
            val left = if (rtl) rowWidth - x - child.measuredWidth else x
            child.layout(left, y, left + child.measuredWidth, y + child.measuredHeight)
        }

        val start = if (rtl) paddingRight else paddingLeft
        val end = rowWidth - (if (rtl) paddingLeft else paddingRight)
        var top = paddingTop

        val titleHeight = max(leading.measuredHeight, title.measuredHeight)
        place(leading, start, top + (titleHeight - leading.measuredHeight) / 2)
        place(title, start + leading.measuredWidth + leadingGap, top + (titleHeight - title.measuredHeight) / 2)
        top += titleHeight + stackGap

        var codeLineHeight = code.measuredHeight
        if (indicator.visibility != View.GONE) {
            if (indicatorBelow) {
                place(code, start, top)
                place(indicator, end - indicator.measuredWidth, top + code.measuredHeight)
                codeLineHeight += indicator.measuredHeight
            } else {
                codeLineHeight = max(code.measuredHeight, indicator.measuredHeight)
                place(code, start, top + (codeLineHeight - code.measuredHeight) / 2)
                place(indicator, end - indicator.measuredWidth, top + (codeLineHeight - indicator.measuredHeight) / 2)
            }
        } else {
            place(code, start, top)
        }
        top += codeLineHeight

        if (progress.visibility != View.GONE) place(progress, start, top + progressGap)
    }

    /**
     * Last resort when even the whole row is narrower than the code: scale
     * the code text down until it fits on one line, so it is never cut.
     * Returns true when the size changed.
     */
    private fun shrinkToFit(rowWidth: Int): Boolean {
        val room = rowWidth - code.totalPaddingLeft - code.totalPaddingRight
        val needed = code.paint.measureText(code.text.toString())
        if (room <= 0 || needed <= room) return false
        code.setTextSize(TypedValue.COMPLEX_UNIT_PX, code.textSize * room / needed * SHRINK_MARGIN)
        return true
    }

    private companion object {
        /** Keeps a scaled-down code clear of rounding at the row's edge. */
        const val SHRINK_MARGIN = 0.98f
    }

    override fun generateDefaultLayoutParams(): LayoutParams =
        LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT)

    private fun exactly(size: Int) = MeasureSpec.makeMeasureSpec(size, MeasureSpec.EXACTLY)

    private fun fixedOrWrap(size: Int, limit: Int) = if (size >= 0) {
        exactly(size)
    } else {
        MeasureSpec.makeMeasureSpec(limit, if (limit > 0) MeasureSpec.AT_MOST else MeasureSpec.UNSPECIFIED)
    }
}
