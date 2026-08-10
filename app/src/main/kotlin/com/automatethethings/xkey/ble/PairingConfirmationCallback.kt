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
package com.automatethethings.xkey.ble

/**
 * Callback interface for handling pairing confirmation requests.
 *
 * When a new device attempts to pair, this callback is invoked to allow
 * the user to confirm or reject the pairing request.
 */
interface PairingConfirmationCallback {
    /**
     * Called when a pairing confirmation is required for an unknown device.
     *
     * @param deviceName The name of the device requesting pairing
     * @param publicKeyFingerprint A short fingerprint of the device's public key for verification
     * @return true if the user confirms the pairing, false if rejected
     */
    suspend fun onPairingConfirmationRequired(
        deviceName: String,
        publicKeyFingerprint: String
    ): Boolean
}
