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

        val content = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
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
            gravity = Gravity.CENTER_VERTICAL
        }

        // Gradient initial circle
        val initialContainer = FrameLayout(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 48),
                UIHelpers.dpToPxInt(context, 48)
            ).apply {
                marginEnd = UIHelpers.dpToPxInt(context, 14)
            }
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

        content.addView(initialContainer)

        // Info column
        val infoColumn = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
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
            maxLines = 1
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

        content.addView(infoColumn)

        // Right section: OTP code, countdown, progress
        val codeSection = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply {
                marginStart = UIHelpers.dpToPxInt(context, 12)
            }
            gravity = Gravity.END
        }

        val codeText = TextView(context).apply {
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

        content.addView(codeSection)

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
