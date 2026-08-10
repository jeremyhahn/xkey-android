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
import android.content.DialogInterface
import android.net.Uri
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.LinearLayout
import android.widget.ScrollView
import com.automatethethings.xkey.R
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

/**
 * Material dialog for adding OATH (TOTP/HOTP) credentials.
 *
 * Supports two input modes:
 * - URI paste: User pastes an `otpauth://` URI and all fields are auto-populated.
 * - Manual entry: User fills in issuer, account name, secret key, and parameters.
 *
 * The dialog builds its custom view programmatically to follow the project's pattern
 * of programmatic UI construction (consistent with SettingsActivity).
 *
 * Default values follow industry standards:
 * - Type: TOTP
 * - Algorithm: SHA1
 * - Digits: 6
 * - Period: 30 seconds
 */
object AddOathDialog {

    /**
     * Show the Add OATH Credential dialog.
     *
     * @param context The activity context for dialog creation.
     * @param onAdd Callback invoked when the user confirms adding a credential.
     *        Parameters: issuer, accountName, secret, type, algorithm, digits, period.
     */
    fun show(
        context: Context,
        onAdd: (
            issuer: String?,
            accountName: String,
            secret: String,
            type: String,
            algorithm: String,
            digits: Int,
            period: Int
        ) -> Unit
    ) {
        val padding = UIHelpers.dpToPxInt(context, 24)
        val fieldSpacing = UIHelpers.dpToPxInt(context, 12)

        // Root scroll view
        val scrollView = ScrollView(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(padding, padding, padding, 0)
        }

        // URI paste field
        val uriInputLayout = createTextInputLayout(
            context,
            "otpauth:// URI or leave empty for manual entry"
        )
        val uriInput = uriInputLayout.editText as TextInputEditText
        uriInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(uriInputLayout)

        // Issuer field
        val issuerInputLayout = createTextInputLayout(
            context,
            "Issuer (e.g., Google)"
        )
        val issuerInput = issuerInputLayout.editText as TextInputEditText
        issuerInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(issuerInputLayout)

        // Account name field
        val accountInputLayout = createTextInputLayout(
            context,
            "Account name (e.g., user@example.com)"
        )
        val accountInput = accountInputLayout.editText as TextInputEditText
        accountInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(accountInputLayout)

        // Secret key field
        val secretInputLayout = createTextInputLayout(
            context,
            "Secret key (Base32)"
        )
        val secretInput = secretInputLayout.editText as TextInputEditText
        secretInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(secretInputLayout)

        // Type dropdown (TOTP / HOTP)
        val typeValues = listOf("TOTP", "HOTP")
        val typeInputLayout = createExposedDropdown(context, "Type", typeValues)
        val typeDropdown = typeInputLayout.editText as AutoCompleteTextView
        typeDropdown.setText("TOTP", false)
        typeInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(typeInputLayout)

        // Algorithm dropdown
        val algorithmValues = listOf("SHA1", "SHA256", "SHA512")
        val algorithmInputLayout = createExposedDropdown(context, "Algorithm", algorithmValues)
        val algorithmDropdown = algorithmInputLayout.editText as AutoCompleteTextView
        algorithmDropdown.setText("SHA1", false)
        algorithmInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(algorithmInputLayout)

        // Digits dropdown
        val digitsValues = listOf("6", "7", "8")
        val digitsInputLayout = createExposedDropdown(context, "Digits", digitsValues)
        val digitsDropdown = digitsInputLayout.editText as AutoCompleteTextView
        digitsDropdown.setText("6", false)
        digitsInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(digitsInputLayout)

        // Period field
        val periodInputLayout = createTextInputLayout(context, "Period (seconds)")
        val periodInput = periodInputLayout.editText as TextInputEditText
        periodInput.inputType = InputType.TYPE_CLASS_NUMBER
        periodInput.setText("30")
        periodInputLayout.layoutParams = createFieldLayoutParams(fieldSpacing)
        container.addView(periodInputLayout)

        scrollView.addView(container)

        // URI auto-fill watcher
        uriInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val uriText = s?.toString()?.trim() ?: return
                if (!uriText.startsWith("otpauth://")) return

                try {
                    val uri = Uri.parse(uriText)
                    parseOtpauthUri(uri)?.let { parsed ->
                        issuerInput.setText(parsed.issuer ?: "")
                        accountInput.setText(parsed.accountName)
                        secretInput.setText(parsed.secret)
                        typeDropdown.setText(parsed.type, false)
                        algorithmDropdown.setText(parsed.algorithm, false)
                        digitsDropdown.setText(parsed.digits.toString(), false)
                        periodInput.setText(parsed.period.toString())
                    }
                } catch (_: Exception) {
                    // Ignore parse errors while user is still typing
                }
            }
        })

        // Build and show dialog.
        //
        // The positive button is wired after the dialog is shown rather than
        // through setPositiveButton's listener, because that listener always
        // dismisses: a form that fails validation has to stay on screen with
        // its errors visible.
        val dialog = MaterialAlertDialogBuilder(context)
            .setTitle("Add Credential")
            .setView(scrollView)
            .setPositiveButton("Add", null)
            .setNegativeButton("Cancel", null)
            .create()

        dialog.setOnShowListener {
            dialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
                // A pasted URI is only ever a way to fill the form: the watcher
                // above copies its parts into the fields, and it is the fields
                // that are submitted. Editing one after pasting therefore wins.
                val issuer = issuerInput.text?.toString()?.trim()?.ifEmpty { null }
                val account = accountInput.text?.toString()?.trim() ?: ""
                val secret = secretInput.text?.toString()?.trim() ?: ""
                val type = typeDropdown.text?.toString()?.trim() ?: "TOTP"
                val algorithm = algorithmDropdown.text?.toString()?.trim() ?: "SHA1"
                val digits = digitsDropdown.text?.toString()?.toIntOrNull() ?: 6
                val period = periodInput.text?.toString()?.toIntOrNull() ?: 30

                // Report both missing fields at once, and say what is wrong
                // here rather than letting the importer reject the assembled
                // URI with a message written for a machine.
                accountInputLayout.error =
                    if (account.isEmpty()) context.getString(R.string.oath_account_required) else null
                secretInputLayout.error =
                    if (secret.isEmpty()) context.getString(R.string.oath_secret_required) else null

                if (account.isNotEmpty() && secret.isNotEmpty()) {
                    onAdd(issuer, account, secret, type, algorithm, digits, period)
                    dialog.dismiss()
                }
            }
        }
        dialog.show()
    }

    // -------------------------------------------------------------------------
    // URI Parsing
    // -------------------------------------------------------------------------

    /**
     * Parsed result from an otpauth:// URI.
     */
    private data class ParsedOtpauth(
        val type: String,
        val issuer: String?,
        val accountName: String,
        val secret: String,
        val algorithm: String,
        val digits: Int,
        val period: Int
    )

    /**
     * Parse an otpauth:// URI into its constituent parts.
     *
     * URI format: `otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30`
     *
     * @param uri The parsed URI.
     * @return Parsed OATH parameters, or null if the URI is invalid.
     */
    private fun parseOtpauthUri(uri: Uri): ParsedOtpauth? {
        val type = uri.host?.uppercase() ?: return null
        if (type != "TOTP" && type != "HOTP") return null

        // Path: /Issuer:account or /account
        val path = uri.path?.removePrefix("/") ?: return null
        val (pathIssuer, accountName) = if (path.contains(":")) {
            val parts = path.split(":", limit = 2)
            parts[0] to parts[1]
        } else {
            null to path
        }

        val secret = uri.getQueryParameter("secret") ?: return null
        val issuer = uri.getQueryParameter("issuer") ?: pathIssuer
        val algorithm = uri.getQueryParameter("algorithm")?.uppercase() ?: "SHA1"
        val digits = uri.getQueryParameter("digits")?.toIntOrNull() ?: 6
        val period = uri.getQueryParameter("period")?.toIntOrNull() ?: 30

        return ParsedOtpauth(
            type = type,
            issuer = issuer,
            accountName = accountName,
            secret = secret,
            algorithm = algorithm,
            digits = digits,
            period = period
        )
    }

    // -------------------------------------------------------------------------
    // View Helpers
    // -------------------------------------------------------------------------

    /**
     * Create a [TextInputLayout] with an enclosed [TextInputEditText].
     */
    private fun createTextInputLayout(
        context: Context,
        hint: String
    ): TextInputLayout {
        val layout = TextInputLayout(
            context,
            null,
            com.google.android.material.R.attr.textInputOutlinedStyle
        ).apply {
            this.hint = hint
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val editText = TextInputEditText(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        layout.addView(editText)
        return layout
    }

    /**
     * Create an exposed dropdown [TextInputLayout] with an [AutoCompleteTextView].
     */
    private fun createExposedDropdown(
        context: Context,
        hint: String,
        items: List<String>
    ): TextInputLayout {
        val layout = TextInputLayout(
            context,
            null,
            com.google.android.material.R.attr.textInputOutlinedExposedDropdownMenuStyle
        ).apply {
            this.hint = hint
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        val autoComplete = AutoCompleteTextView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            inputType = InputType.TYPE_NULL
            setAdapter(
                ArrayAdapter(context, android.R.layout.simple_dropdown_item_1line, items)
            )
        }

        layout.addView(autoComplete)
        return layout
    }

    /**
     * Create [LinearLayout.LayoutParams] with bottom margin for field spacing.
     */
    private fun createFieldLayoutParams(bottomMargin: Int): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            this.bottomMargin = bottomMargin
        }
    }
}
