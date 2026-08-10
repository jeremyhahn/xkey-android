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
import android.text.format.DateUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.entity.KeyEntity

/**
 * RecyclerView adapter for displaying FIDO2 passkeys with premium card UI.
 *
 * Each item shows a gradient icon circle, RP name, username, feature badges
 * (discoverable, biometric, StrongBox), relative last-used date, and a chevron.
 * Uses programmatic card building with [PremiumCardFactory] for consistent styling.
 *
 * @param onItemClick Callback when a passkey item is tapped.
 * @param onItemLongClick Callback when a passkey item is long-pressed.
 */
class PasskeyAdapter(
    private val onItemClick: (KeyEntity) -> Unit,
    private val onItemLongClick: (KeyEntity) -> Boolean
) : ListAdapter<KeyEntity, PasskeyAdapter.ViewHolder>(PasskeyDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(buildPremiumPasskeyCard(parent.context))
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    private fun buildPremiumPasskeyCard(context: Context): com.google.android.material.card.MaterialCardView {
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

        // Gradient icon circle
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
            setImageResource(R.drawable.ic_key_fido2)
            layoutParams = FrameLayout.LayoutParams(
                UIHelpers.dpToPxInt(context, 28),
                UIHelpers.dpToPxInt(context, 28)
            ).apply {
                gravity = Gravity.CENTER
            }
            imageTintList = ColorStateList.valueOf(
                ContextCompat.getColor(context, R.color.on_primary)
            )
        }
        iconContainer.addView(iconView)

        // Apply gradient background to icon container
        val gradientStart = ContextCompat.getColor(context, R.color.primary_40)
        val gradientEnd = ContextCompat.getColor(context, R.color.primary_60)
        val gradient = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(gradientStart, gradientEnd)
        ).apply {
            cornerRadius = UIHelpers.dpToPx(context, 24f)
        }
        iconContainer.background = gradient

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

        val rpNameText = TextView(context).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurface
            ))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            tag = "rpName"
        }
        infoColumn.addView(rpNameText)

        val userNameText = TextView(context).apply {
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
            tag = "userName"
        }
        infoColumn.addView(userNameText)

        // Badge row
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

        // Right section: last used + chevron
        val rightSection = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            gravity = Gravity.CENTER_VERTICAL or Gravity.END
        }

        val lastUsedText = TextView(context).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_LabelSmall)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            tag = "lastUsed"
        }
        rightSection.addView(lastUsedText)

        content.addView(rightSection)

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

        private val rpNameView: TextView = itemView.findViewWithTag("rpName")
        private val userNameView: TextView = itemView.findViewWithTag("userName")
        private val badgeRow: LinearLayout = itemView.findViewWithTag("badgeRow")
        private val lastUsedView: TextView = itemView.findViewWithTag("lastUsed")

        fun bind(key: KeyEntity) {
            // RP name
            rpNameView.text = key.rpName ?: key.rpId ?: key.label

            // Username
            val userName = key.userName ?: key.userDisplayName
            if (userName != null) {
                userNameView.text = userName
                userNameView.visibility = View.VISIBLE
            } else {
                userNameView.visibility = View.GONE
            }

            // Badges
            badgeRow.removeAllViews()

            if (key.isDiscoverable) {
                badgeRow.addView(createBadge(
                    itemView.context,
                    "Discoverable",
                    ContextCompat.getColor(itemView.context, R.color.primary),
                    ContextCompat.getColor(itemView.context, R.color.on_primary)
                ))
            }

            if (key.biometricRequired) {
                badgeRow.addView(createBadge(
                    itemView.context,
                    itemView.context.getString(R.string.key_badge_biometric),
                    ContextCompat.getColor(itemView.context, R.color.secondary),
                    ContextCompat.getColor(itemView.context, R.color.on_secondary)
                ))
            }

            if (key.strongBoxBacked) {
                badgeRow.addView(createBadge(
                    itemView.context,
                    itemView.context.getString(R.string.key_badge_strongbox),
                    ContextCompat.getColor(itemView.context, R.color.tertiary),
                    ContextCompat.getColor(itemView.context, R.color.on_tertiary)
                ))
            }

            // Last used date
            if (key.lastUsedAt > 0) {
                lastUsedView.text = DateUtils.getRelativeTimeSpanString(
                    key.lastUsedAt,
                    System.currentTimeMillis(),
                    DateUtils.MINUTE_IN_MILLIS,
                    DateUtils.FORMAT_ABBREV_RELATIVE
                )
            } else {
                lastUsedView.text = itemView.context.getString(R.string.passkey_never_used)
            }

            // Click handlers
            itemView.setOnClickListener { onItemClick(key) }
            itemView.setOnLongClickListener { onItemLongClick(key) }
        }

        private fun createBadge(context: Context, text: String, bgColor: Int, textColor: Int): TextView {
            return TextView(context).apply {
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

    class PasskeyDiffCallback : DiffUtil.ItemCallback<KeyEntity>() {

        override fun areItemsTheSame(oldItem: KeyEntity, newItem: KeyEntity): Boolean {
            return oldItem.keyId == newItem.keyId
        }

        override fun areContentsTheSame(oldItem: KeyEntity, newItem: KeyEntity): Boolean {
            return oldItem.keyId == newItem.keyId &&
                oldItem.rpName == newItem.rpName &&
                oldItem.userName == newItem.userName &&
                oldItem.lastUsedAt == newItem.lastUsedAt &&
                oldItem.useCount == newItem.useCount
        }
    }
}
