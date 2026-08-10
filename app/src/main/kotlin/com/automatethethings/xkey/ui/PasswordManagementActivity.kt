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

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * Local management UI for the encrypted password store.
 *
 * Lists stored passwords, supports add / view / delete, and never renders a
 * password value in the list — it is revealed only in the detail dialog. The
 * underlying values are encrypted at rest by [PasswordRepository]; the same
 * store backs the `local.syncPasswords` / `remote.syncPasswords` sync surface.
 */
class PasswordManagementActivity : AppCompatActivity() {

    private val repository: PasswordRepository by lazy {
        PasswordRepository(XKeyDatabase.getInstance(this).passwordDao())
    }

    private lateinit var adapter: PasswordAdapter
    private lateinit var emptyView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        adapter = PasswordAdapter { showDetailDialog(it) }

        val toolbarContainer = buildPremiumToolbar()

        val recycler = RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@PasswordManagementActivity)
            adapter = this@PasswordManagementActivity.adapter
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        emptyView = TextView(this).apply {
            text = getString(R.string.password_empty_message)
            gravity = Gravity.CENTER
            alpha = 0.6f
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val fab = ExtendedFloatingActionButton(this).apply {
            text = getString(R.string.password_add_fab)
            setIconResource(android.R.drawable.ic_input_add)
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM or Gravity.END
            ).apply {
                val margin = UIHelpers.dpToPxInt(this@PasswordManagementActivity, 20)
                setMargins(0, 0, margin, margin)
            }
            setOnClickListener { showAddDialog() }
        }

        val content = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            addView(recycler)
            addView(emptyView)
            addView(fab)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            addView(toolbarContainer)
            addView(content)
        }

        setContentView(root)
        reload()
    }

    /**
     * Builds the app's gradient toolbar (navy gradient, on_primary title and a
     * dimmed subtitle) to match [KeyManagementActivity].
     *
     * TODO: replace with the shared `PremiumToolbar.install(...)` helper once it lands.
     */
    private fun buildPremiumToolbar(): LinearLayout {
        val toolbarContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(
                    ContextCompat.getColor(
                        this@PasswordManagementActivity,
                        R.color.gradient_primary_start
                    ),
                    ContextCompat.getColor(
                        this@PasswordManagementActivity,
                        R.color.gradient_primary_end
                    )
                )
            )
        }

        val toolbar = MaterialToolbar(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                UIHelpers.resolveActionBarSize(this@PasswordManagementActivity)
            )
            setBackgroundColor(Color.TRANSPARENT)
            elevation = 0f
            title = getString(R.string.passwords_title)
            setTitleTextColor(
                ContextCompat.getColor(this@PasswordManagementActivity, R.color.on_primary)
            )
            setNavigationIcon(R.drawable.ic_chevron_right)
            navigationIcon?.setTint(
                ContextCompat.getColor(this@PasswordManagementActivity, R.color.on_primary)
            )
            setNavigationOnClickListener { finish() }
        }

        val subtitle = TextView(this).apply {
            text = getString(R.string.passwords_card_desc)
            setTextColor(UIHelpers.applyAlpha(
                ContextCompat.getColor(this@PasswordManagementActivity, R.color.on_primary),
                0.85f
            ))
            textSize = 14f
            setPadding(
                UIHelpers.dpToPxInt(this@PasswordManagementActivity, 72),
                0,
                UIHelpers.dpToPxInt(this@PasswordManagementActivity, 16),
                UIHelpers.dpToPxInt(this@PasswordManagementActivity, 12)
            )
        }

        toolbarContainer.addView(toolbar)
        toolbarContainer.addView(subtitle)
        return toolbarContainer
    }

    private fun reload() {
        lifecycleScope.launch {
            val items = repository.list().sortedBy { (it.title ?: it.name).lowercase() }
            adapter.submit(items)
            emptyView.visibility = if (items.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
        }
    }

    private fun labeledField(label: String, password: Boolean = false): Pair<LinearLayout, EditText> {
        val tv = TextView(this).apply {
            text = label
            alpha = 0.7f
            setPadding(0, UIHelpers.dpToPxInt(this@PasswordManagementActivity, 8), 0, 0)
        }
        val et = EditText(this).apply {
            inputType = if (password) {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            } else {
                InputType.TYPE_CLASS_TEXT
            }
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(tv)
            addView(et)
        }
        return box to et
    }

    private fun showAddDialog() {
        val (nameBox, nameEt) = labeledField(getString(R.string.password_field_name))
        val (userBox, userEt) = labeledField(getString(R.string.password_field_username))
        val (passBox, passEt) = labeledField(
            getString(R.string.password_field_password),
            password = true
        )
        val (urlBox, urlEt) = labeledField(getString(R.string.password_field_url))
        val (notesBox, notesEt) = labeledField(getString(R.string.password_field_notes))

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val hPad = UIHelpers.dpToPxInt(this@PasswordManagementActivity, 24)
            val vPad = UIHelpers.dpToPxInt(this@PasswordManagementActivity, 8)
            setPadding(hPad, vPad, hPad, vPad)
            addView(nameBox); addView(userBox); addView(passBox); addView(urlBox); addView(notesBox)
        }
        val scroll = ScrollView(this).apply { addView(container) }

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.password_add_title)
            .setView(scroll)
            .setPositiveButton(R.string.password_save) { _, _ ->
                val name = nameEt.text.toString().trim()
                val password = passEt.text.toString()
                if (name.isEmpty() || password.isEmpty()) {
                    Toast.makeText(
                        this,
                        R.string.password_required,
                        Toast.LENGTH_SHORT
                    ).show()
                    return@setPositiveButton
                }
                lifecycleScope.launch {
                    repository.upsert(
                        PasswordRecord(
                            passwordId = "pwd-${UUID.randomUUID()}",
                            name = name,
                            title = name,
                            username = userEt.text.toString().trim().ifBlank { null },
                            password = password,
                            url = urlEt.text.toString().trim().ifBlank { null },
                            notes = notesEt.text.toString().trim().ifBlank { null },
                            source = "local"
                        )
                    )
                    reload()
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun showDetailDialog(record: PasswordRecord) {
        val details = buildString {
            append(getString(R.string.password_detail_name, record.name)).append("\n")
            record.username?.takeIf { it.isNotBlank() }?.let {
                append(getString(R.string.password_detail_username, it)).append("\n")
            }
            append(getString(R.string.password_detail_password, record.password)).append("\n")
            record.url?.takeIf { it.isNotBlank() }?.let {
                append(getString(R.string.password_detail_url, it)).append("\n")
            }
            record.notes?.takeIf { it.isNotBlank() }?.let {
                append(getString(R.string.password_detail_notes, it)).append("\n")
            }
        }.trimEnd()

        MaterialAlertDialogBuilder(this)
            .setTitle(record.title?.takeIf { it.isNotBlank() } ?: record.name)
            .setMessage(details)
            .setPositiveButton(R.string.password_copy) { _, _ -> copyPassword(record.password) }
            .setNeutralButton(R.string.password_delete) { _, _ -> confirmDelete(record) }
            .setNegativeButton(R.string.password_close, null)
            .show()
    }

    private fun confirmDelete(record: PasswordRecord) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.password_delete_title)
            .setMessage(getString(
                R.string.password_delete_message,
                record.title ?: record.name
            ))
            .setPositiveButton(R.string.password_delete) { _, _ ->
                lifecycleScope.launch {
                    repository.delete(record.passwordId)
                    reload()
                }
            }
            .setNegativeButton(R.string.button_cancel, null)
            .show()
    }

    private fun copyPassword(password: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("password", password).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)
        Toast.makeText(this, R.string.password_copied, Toast.LENGTH_SHORT).show()
    }
}
