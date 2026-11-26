/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.credential.handler

import android.util.Log
import androidx.credentials.provider.CallingAppInfo
import com.automatethethings.xkey.credential.RelyingPartyOrigin

/**
 * The one place a passkey ceremony decides whether its caller may speak for
 * a relying party.
 *
 * Every request, whether it brings its own clientDataHash or lets this
 * provider build clientDataJSON, needs a privileged browser whose
 * framework-verified origin the RP ID is valid for. A caller that supplies
 * its own hash chooses the origin the relying party will see, so an app
 * without a verified browser origin must never have its hash signed.
 */
internal object CallerOrigin {

    private const val TAG = "CallerOrigin"

    /**
     * Returns the caller's verified origin, or throws the exception [refuse]
     * builds when the caller has no populated origin, is not a privileged
     * browser, or is on an origin [rpId] is not valid for.
     */
    fun verify(
        callingAppInfo: CallingAppInfo,
        rpId: String,
        refuse: (String, Throwable?) -> Exception
    ): String {
        val callingPackage = callingAppInfo.packageName
        if (!callingAppInfo.isOriginPopulated()) {
            throw refuse("Calling app $callingPackage has no verified web origin", null)
        }
        val verifiedOrigin = try {
            callingAppInfo.getOrigin(BrowserAllowlist.PRIVILEGED_BROWSERS)
        } catch (e: Exception) {
            Log.e(TAG, "Origin verification failed for $callingPackage", e)
            throw refuse("Could not verify the calling app's origin ($callingPackage)", e)
        }
        val origin = verifiedOrigin
            ?: throw refuse("Calling app $callingPackage has no verified web origin", null)

        // The origin goes into clientDataJSON and the rpId is hashed into
        // authenticator data. Signing a response where they are unrelated
        // would let an app act for a site it does not control.
        if (!RelyingPartyOrigin.isRpIdValidForOrigin(rpId, origin)) {
            throw refuse("Relying party $rpId is not valid for the caller's origin $origin", null)
        }
        return origin
    }
}
