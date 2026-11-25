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

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathCurrentCode
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * What the OATH details screen shows. Holds no secret: the code is computed
 * from the secret inside the view model and only the code leaves it.
 *
 * [periodSeconds] and [secondsLeft] are set for TOTP only, [counter] for
 * HOTP only; [remoteDeviceId] only for a credential synced from a device.
 * [code] and [secondsLeft] are null when no code can be computed (the secret
 * cannot be decrypted or the engine refuses a stored value); every other
 * field is still filled.
 */
data class OathCredentialDetails(
    val oathId: String,
    val issuer: String?,
    val accountName: String,
    val type: String,
    val algorithm: String,
    val digits: Int,
    val periodSeconds: Int?,
    val counter: Long?,
    val createdAt: Long,
    val lastUsedAt: Long?,
    val useCount: Int,
    val source: String,
    val remoteDeviceId: String?,
    val code: String?,
    val secondsLeft: Int?
)

/** The details screen's state. */
sealed interface OathCredentialDetailUiState {
    /** Not read yet. */
    data object Loading : OathCredentialDetailUiState

    /** The credential and its current code. */
    data class Shown(val details: OathCredentialDetails) : OathCredentialDetailUiState

    /** The credential no longer exists (deleted while the screen was open): close. */
    data object Gone : OathCredentialDetailUiState
}

/**
 * Backs [OathCredentialDetailActivity]: reads the credential [oathId] and
 * computes its current code each second ([run]) off an injectable [clock].
 *
 * @param load Reads a credential by oathId (`OathCredentialDao.getByOathId`).
 * @param secretOf Decrypts a credential's secret for code generation only.
 * @param clock Wall clock in milliseconds.
 */
class OathCredentialDetailViewModel(
    private val oathId: String,
    private val load: suspend (String) -> OathCredentialEntity?,
    private val secretOf: (OathCredentialEntity) -> ByteArray,
    private val clock: () -> Long = System::currentTimeMillis
) : ViewModel() {

    private val _state = MutableStateFlow<OathCredentialDetailUiState>(OathCredentialDetailUiState.Loading)
    val state: StateFlow<OathCredentialDetailUiState> = _state.asStateFlow()

    private var current: OathCredentialEntity? = null

    /** Read the credential again and recompute the code and the time left. */
    suspend fun refresh() {
        val credential = load(oathId)
        current = credential
        _state.value = if (credential == null) {
            OathCredentialDetailUiState.Gone
        } else {
            OathCredentialDetailUiState.Shown(detailsOf(credential, clock()))
        }
    }

    /**
     * Refresh every second until cancelled (the screen runs this while it is
     * started) or until the credential is gone.
     */
    suspend fun run(tickMillis: Long = TICK_MILLIS) {
        while (true) {
            refresh()
            if (_state.value == OathCredentialDetailUiState.Gone) return
            delay(tickMillis - clock() % tickMillis)
        }
    }

    /**
     * Copy the current code through [clipboard] (an HOTP copy advances the
     * counter) and refresh. Returns the code copied, or null when nothing is
     * shown or no code can be computed (the clipboard is then left alone).
     */
    suspend fun copy(clipboard: OathCodeClipboard): String? {
        val credential = current ?: return null
        val shown = (_state.value as? OathCredentialDetailUiState.Shown)?.details ?: return null
        // Off while no code can be computed; when one can, the clipboard
        // generates it afresh rather than copying the last tick's code.
        if (shown.code == null) return null
        val copied = clipboard.copy(credential.oathId)
        refresh()
        return copied
    }

    private fun detailsOf(credential: OathCredentialEntity, now: Long): OathCredentialDetails {
        val totp = credential.oathType == TOTP
        val current = OathCurrentCode.currentCode(credential, secretOf, now) as? OathCurrentCode.Available
        return OathCredentialDetails(
            oathId = credential.oathId,
            issuer = credential.issuer,
            accountName = credential.accountName,
            type = credential.oathType,
            algorithm = credential.algorithm,
            digits = credential.digits,
            periodSeconds = if (totp) credential.periodSeconds else null,
            counter = if (totp) null else credential.counter,
            createdAt = credential.createdAt,
            lastUsedAt = credential.lastUsedAt,
            useCount = credential.useCount,
            source = credential.source,
            remoteDeviceId = credential.remoteDeviceId,
            code = current?.code,
            secondsLeft = current?.secondsLeft
        )
    }

    companion object {
        private const val TOTP = "TOTP"
        const val TICK_MILLIS = 1000L

        /** A factory for [oathId] with the given data sources. */
        fun factory(
            oathId: String,
            load: suspend (String) -> OathCredentialEntity?,
            secretOf: (OathCredentialEntity) -> ByteArray
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>, extras: CreationExtras): T =
                OathCredentialDetailViewModel(oathId, load, secretOf) as T
        }
    }
}
