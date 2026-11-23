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

        // The code section is measured first and never shrinks; on a narrow
        // row or with a large font it drops below the issuer and account.
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
            leadingGap = UIHelpers.dpToPxInt(context, 14)
            codeGap = UIHelpers.dpToPxInt(context, 12)
            stackGap = UIHelpers.dpToPxInt(context, 8)
            minInfoWidth = UIHelpers.dpToPxInt(context, MIN_INFO_WIDTH_DP)
        }

        // Gradient initial circle
        val initialContainer = FrameLayout(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                UIHelpers.dpToPxInt(context, 48),
                UIHelpers.dpToPxInt(context, 48)
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
            textSize = 20f
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
            cornerRadius = UIHelpers.dpToPx(context, 24f)
        }
        initialContainer.background = gradient

        // Info column: issuer and account ellipsize; the code never does.
        val infoColumn = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val issuerText = TextView(context).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
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
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelMedium)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            maxLines = 2
            ellipsize = android.text.TextUtils.TruncateAt.END
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 2)
            }
            tag = "account"
        }
        infoColumn.addView(accountText)

        // Code section: OTP code, countdown, progress
        val codeSection = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.END
            tag = "codeSection"
        }

        val codeText = TextView(context).apply {
            // A vertical LinearLayout defaults a child to MATCH_PARENT, which
            // let the section shrink the code to the countdown's width.
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            keepWhole()
            textSize = 24f
            typeface = Typeface.MONOSPACE
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                androidx.appcompat.R.attr.colorPrimary
            ))
            letterSpacing = 0.1f
            tag = "code"
        }
        codeSection.addView(codeText)

        val countdownText = TextView(context).apply {
            keepWhole()
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 2)
            }
            gravity = Gravity.END
            tag = "countdown"
        }
        codeSection.addView(countdownText)

        val progressBar = ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.dpToPxInt(context, 4)
            ).apply {
                topMargin = UIHelpers.dpToPxInt(context, 4)
            }
            progressTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, androidx.appcompat.R.attr.colorPrimary)
            )
            progressBackgroundTintList = ColorStateList.valueOf(
                UIHelpers.resolveThemeColor(context, com.google.android.material.R.attr.colorSurfaceVariant)
            )
            tag = "progress"
        }
        codeSection.addView(progressBar)

        content.setChildren(initialContainer, infoColumn, codeSection)
        content.fitText = codeText

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
        /** The narrowest issuer/account column the code may sit beside, in dp. */
        const val MIN_INFO_WIDTH_DP = 96

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
 * The OATH list row: a leading badge, the issuer/account column and the
 * code section. The code section is measured first at its full natural
 * width and never shrinks; the info column takes what is left. When less
 * than [minInfoWidth] would be left (a narrow screen or a large font), the
 * code section drops below the badge and info column and spans the row.
 *
 * Children are added with [setChildren]; the row mirrors for right-to-left
 * layouts.
 */
internal class OathRowLayout(context: Context) : ViewGroup(context) {

    private lateinit var leading: View
    private lateinit var info: View
    private lateinit var code: View

    /** Space after the leading badge. */
    var leadingGap: Int = 0

    /** Space between the info column and the code section side by side. */
    var codeGap: Int = 0

    /** Space above the code section once it drops below. */
    var stackGap: Int = 0

    /** The narrowest info column the code section may sit beside. */
    var minInfoWidth: Int = 0

    /**
     * The code text inside the code section. Only when the code is wider
     * than the whole row is its text size scaled down to keep it on one line.
     */
    var fitText: TextView? = null
        set(value) {
            field = value
            fitTextSize = 0f
        }

    private var fitTextSize = 0f

    /** True when the last measure put the code section below the info column. */
    var isStacked: Boolean = false
        private set

    fun setChildren(leading: View, info: View, code: View) {
        removeAllViews()
        this.leading = leading
        this.info = info
        this.code = code
        addView(leading)
        addView(info)
        addView(code)
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val inner = max(0, width - paddingLeft - paddingRight)
        val unspecified = MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED)

        fitText?.let { text ->
            if (fitTextSize == 0f) fitTextSize = text.textSize
            if (text.textSize != fitTextSize) text.setTextSize(TypedValue.COMPLEX_UNIT_PX, fitTextSize)
        }

        leading.measure(fixedOrWrap(leading.layoutParams.width, inner), fixedOrWrap(leading.layoutParams.height, 0))
        code.measure(MeasureSpec.makeMeasureSpec(inner, MeasureSpec.AT_MOST), unspecified)

        val topWidth = max(0, inner - leading.measuredWidth - leadingGap)
        val besideCode = topWidth - codeGap - code.measuredWidth
        isStacked = besideCode < minInfoWidth

        val contentHeight = if (isStacked) {
            info.measure(exactly(topWidth), unspecified)
            code.measure(exactly(inner), unspecified)
            if (shrinkToFit(inner)) code.measure(exactly(inner), unspecified)
            max(leading.measuredHeight, info.measuredHeight) + stackGap + code.measuredHeight
        } else {
            info.measure(exactly(besideCode), unspecified)
            maxOf(leading.measuredHeight, info.measuredHeight, code.measuredHeight)
        }
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
        val top = paddingTop
        val infoStart = start + leading.measuredWidth + leadingGap
        if (isStacked) {
            val topHeight = max(leading.measuredHeight, info.measuredHeight)
            place(leading, start, top + (topHeight - leading.measuredHeight) / 2)
            place(info, infoStart, top + (topHeight - info.measuredHeight) / 2)
            place(code, start, top + topHeight + stackGap)
        } else {
            val height = (b - t) - paddingTop - paddingBottom
            place(leading, start, top + (height - leading.measuredHeight) / 2)
            place(info, infoStart, top + (height - info.measuredHeight) / 2)
            place(code, infoStart + info.measuredWidth + codeGap, top + (height - code.measuredHeight) / 2)
        }
    }

    /**
     * Last resort when even the whole row is narrower than the code: scale
     * [fitText] down until it fits on one line, so it is never cut. Returns
     * true when the size changed.
     */
    private fun shrinkToFit(rowWidth: Int): Boolean {
        val text = fitText ?: return false
        val room = rowWidth - code.paddingLeft - code.paddingRight -
            text.totalPaddingLeft - text.totalPaddingRight
        val needed = text.paint.measureText(text.text.toString())
        if (room <= 0 || needed <= room) return false
        text.setTextSize(TypedValue.COMPLEX_UNIT_PX, text.textSize * room / needed * SHRINK_MARGIN)
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
