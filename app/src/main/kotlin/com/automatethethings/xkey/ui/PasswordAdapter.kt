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
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.password.PasswordRecord
import com.google.android.material.card.MaterialCardView

/**
 * RecyclerView adapter for the password manager list. Rows are built
 * programmatically (consistent with the app's code-driven UI) and never display
 * the password value itself — that is revealed only in the detail dialog.
 *
 * Rows use [PremiumCardFactory.createElevatedCard] so the list matches the OATH
 * and passkey lists, and the list is diffed like every sibling adapter so that a
 * reload animates the rows that actually changed instead of rebinding the lot.
 */
class PasswordAdapter(
    private val onClick: (PasswordRecord) -> Unit
) : ListAdapter<PasswordRecord, PasswordAdapter.ViewHolder>(PasswordDiffCallback()) {

    class ViewHolder(
        val card: MaterialCardView,
        val title: TextView,
        val subtitle: TextView
    ) : RecyclerView.ViewHolder(card)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val context = parent.context

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
            orientation = LinearLayout.VERTICAL
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
        }

        val title = TextView(context).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurface
            ))
        }
        val subtitle = TextView(context).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTextColor(UIHelpers.resolveThemeColor(
                context,
                com.google.android.material.R.attr.colorOnSurfaceVariant
            ))
            gravity = Gravity.START
        }
        content.addView(title)
        content.addView(subtitle)
        card.addView(content)
        return ViewHolder(card, title, subtitle)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.title.text = item.title?.takeIf { it.isNotBlank() } ?: item.name
        val sub = buildString {
            item.username?.takeIf { it.isNotBlank() }?.let { append(it) }
            item.url?.takeIf { it.isNotBlank() }?.let {
                if (isNotEmpty()) append("  ·  ")
                append(it)
            }
        }
        holder.subtitle.text = sub.ifEmpty { item.name }
        holder.itemView.setOnClickListener { onClick(item) }
    }

    /** Replace the displayed list, animating only the rows that changed. */
    fun submit(newItems: List<PasswordRecord>) {
        submitList(newItems)
    }

    /**
     * Identity is the immutable [PasswordRecord.passwordId]; content is everything
     * the row renders, which is the title, the username and the URL. The password
     * value itself is deliberately excluded: it is never shown in the list, so a
     * changed password must not redraw the row.
     */
    class PasswordDiffCallback : DiffUtil.ItemCallback<PasswordRecord>() {

        override fun areItemsTheSame(oldItem: PasswordRecord, newItem: PasswordRecord): Boolean {
            return oldItem.passwordId == newItem.passwordId
        }

        override fun areContentsTheSame(oldItem: PasswordRecord, newItem: PasswordRecord): Boolean {
            return oldItem.title == newItem.title &&
                oldItem.name == newItem.name &&
                oldItem.username == newItem.username &&
                oldItem.url == newItem.url
        }
    }
}
