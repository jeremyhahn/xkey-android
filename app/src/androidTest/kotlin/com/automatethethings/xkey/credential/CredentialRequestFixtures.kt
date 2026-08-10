/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.credential

import android.content.pm.SigningInfo
import android.os.Bundle
import android.util.Base64
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialOption
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Builders for the WebAuthn request shapes the credential provider receives.
 *
 * `ProviderCreateCredentialRequest`, `ProviderGetCredentialRequest` and
 * `CallingAppInfo` all have public constructors in androidx.credentials 1.3.0,
 * so a test can hand the handlers exactly what the framework would — including
 * the two cases that decide whether a ceremony is allowed at all: a caller with
 * no verified web origin, and a caller claiming an origin it is not privileged
 * to use.
 */
object CredentialRequestFixtures {

    /** COSE identifier for ES256, the only algorithm this authenticator mints. */
    const val COSE_ES256 = -7

    /** An RS256-only request, which this authenticator must refuse. */
    const val COSE_RS256 = -257

    /**
     * A caller with no origin at all — an ordinary app. `getOrigin` returns
     * null for it, which the handlers must treat as "refuse", not as
     * "invent https://<rpId>".
     */
    fun appWithoutOrigin(packageName: String = "com.example.testcaller"): CallingAppInfo =
        CallingAppInfo(packageName, SigningInfo())

    /**
     * A caller that claims a web origin but is not on the privileged browser
     * allowlist. `getOrigin(allowlist)` throws for it, exercising the handlers'
     * origin-verification failure branch.
     */
    fun unprivilegedAppClaimingOrigin(
        packageName: String = "com.example.fakebrowser",
        origin: String = "https://not-my-site.example.com"
    ): CallingAppInfo = CallingAppInfo(packageName, SigningInfo(), origin)

    /** A registration request in the shape Chrome/Vanadium send. */
    fun createRequestJson(
        rpId: String,
        rpName: String = "Fixture RP",
        userId: String = "dXNlci1pZA",
        userName: String = "user@example.com",
        userDisplayName: String = "Fixture User",
        challenge: String = "Y2hhbGxlbmdl",
        algorithms: List<Int> = listOf(COSE_ES256),
        userVerification: String? = null,
        residentKey: String? = null,
        excludeCredentialIds: List<String> = emptyList(),
        omitRp: Boolean = false
    ): String = JSONObject().apply {
        put("challenge", challenge)
        if (!omitRp) {
            put("rp", JSONObject().put("id", rpId).put("name", rpName))
        }
        put(
            "user",
            JSONObject()
                .put("id", userId)
                .put("name", userName)
                .put("displayName", userDisplayName)
        )
        put(
            "pubKeyCredParams",
            JSONArray().apply {
                algorithms.forEach { put(JSONObject().put("type", "public-key").put("alg", it)) }
            }
        )
        if (userVerification != null || residentKey != null) {
            put(
                "authenticatorSelection",
                JSONObject().apply {
                    userVerification?.let { put("userVerification", it) }
                    residentKey?.let { put("residentKey", it) }
                }
            )
        }
        if (excludeCredentialIds.isNotEmpty()) {
            put(
                "excludeCredentials",
                JSONArray().apply {
                    excludeCredentialIds.forEach {
                        put(JSONObject().put("type", "public-key").put("id", it))
                    }
                }
            )
        }
    }.toString()

    /** An assertion request in the shape Chrome/Vanadium send. */
    fun getRequestJson(
        rpId: String,
        challenge: String = "Y2hhbGxlbmdl",
        userVerification: String? = null,
        allowCredentialIds: List<String> = emptyList(),
        omitChallenge: Boolean = false
    ): String = JSONObject().apply {
        put("rpId", rpId)
        if (!omitChallenge) {
            put("challenge", challenge)
        }
        userVerification?.let { put("userVerification", it) }
        if (allowCredentialIds.isNotEmpty()) {
            put(
                "allowCredentials",
                JSONArray().apply {
                    allowCredentialIds.forEach {
                        put(JSONObject().put("type", "public-key").put("id", it))
                    }
                }
            )
        }
    }.toString()

    /** Decodes a WebAuthn base64url field. */
    fun decodeUrl(value: String): ByteArray =
        Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    /** Encodes bytes the way WebAuthn identifies credentials. */
    fun encodeUrl(value: ByteArray): String =
        Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    /**
     * The `clientDataHash` a privileged browser supplies through Credential
     * Manager. Its presence is what lets a ceremony skip origin verification:
     * the browser, not this provider, authored and will bind the client data.
     */
    val BROWSER_CLIENT_DATA_HASH: ByteArray =
        MessageDigest.getInstance("SHA-256").digest("xkey-fixture-client-data".toByteArray())

    // ---------------------------------------------------------------------
    // Framework request objects
    // ---------------------------------------------------------------------

    /**
     * The final-phase registration request, exactly as
     * `CredentialProviderService` would hand it to the handler.
     *
     * @param clientDataHash non-null models a privileged browser; null forces
     *        the provider to author client data itself, which requires a
     *        verified origin for [callingAppInfo].
     */
    fun providerCreateRequest(
        requestJson: String,
        clientDataHash: ByteArray? = BROWSER_CLIENT_DATA_HASH,
        callingAppInfo: CallingAppInfo = appWithoutOrigin()
    ): ProviderCreateCredentialRequest = ProviderCreateCredentialRequest(
        CreatePublicKeyCredentialRequest(
            requestJson = requestJson,
            clientDataHash = clientDataHash
        ),
        callingAppInfo
    )

    /** The final-phase assertion request. See [providerCreateRequest]. */
    fun providerGetRequest(
        requestJson: String,
        clientDataHash: ByteArray? = BROWSER_CLIENT_DATA_HASH,
        callingAppInfo: CallingAppInfo = appWithoutOrigin()
    ): ProviderGetCredentialRequest = ProviderGetCredentialRequest(
        listOf(
            GetPublicKeyCredentialOption(
                requestJson = requestJson,
                clientDataHash = clientDataHash
            )
        ),
        callingAppInfo
    )

    /** The begin-phase registration request the system UI drives. */
    fun beginCreateRequest(
        requestJson: String,
        callingAppInfo: CallingAppInfo = appWithoutOrigin()
    ): BeginCreatePublicKeyCredentialRequest =
        BeginCreatePublicKeyCredentialRequest(requestJson, callingAppInfo, Bundle())

    /** A single public-key option for the begin-phase assertion request. */
    fun beginGetOption(
        requestJson: String,
        id: String = "fixture-option"
    ): BeginGetPublicKeyCredentialOption =
        BeginGetPublicKeyCredentialOption(Bundle(), id, requestJson)

    /** The begin-phase assertion request the system UI drives. */
    fun beginGetRequest(
        options: List<BeginGetCredentialOption>,
        callingAppInfo: CallingAppInfo = appWithoutOrigin()
    ): BeginGetCredentialRequest = BeginGetCredentialRequest(options, callingAppInfo)
}
