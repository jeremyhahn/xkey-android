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
package com.automatethethings.xkey.protocol

/**
 * A session binding with a pinned SAS, shared by [ShortAuthStringTest] and the
 * phone-initiated SAS tests: the code was computed outside this codebase
 * (SHA-256 over the `xkey-attest-channel-v1` channel binding, then go-xkms
 * `formatShortAuthString`), so both ends of a session derive this value.
 */
object SasTestVectors {
    val INITIATOR_STATIC_KEY: ByteArray = ByteArray(32) { 0x11 }
    val RESPONDER_STATIC_KEY: ByteArray = ByteArray(32) { 0x22 }
    val PROLOGUE: ByteArray = ByteArray(32) { 0x33 }

    const val FIXED_BINDING_SAS = "3181-4707-2325"

    fun fixedBinding(): SessionBinding =
        SessionBinding(INITIATOR_STATIC_KEY.copyOf(), RESPONDER_STATIC_KEY.copyOf(), PROLOGUE.copyOf())
}
