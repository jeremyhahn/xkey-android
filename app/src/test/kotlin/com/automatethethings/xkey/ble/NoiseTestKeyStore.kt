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

package com.automatethethings.xkey.ble

import com.automatethethings.xkey.settings.InMemorySharedPreferences

/**
 * The static-key store unit tests run [NoiseSession.loadStaticKey] against.
 *
 * Off-device there is no Android Keystore, and `loadStaticKey` fails closed
 * when its encrypted store cannot be opened. [install] puts an in-memory store
 * in its place: every open returns an empty store, so each session generates
 * (and saves) a fresh static key, as a fresh install would.
 */
internal object NoiseTestKeyStore {
    fun install() {
        NoiseSession.keyStoreOpener = { InMemorySharedPreferences() }
    }
}
