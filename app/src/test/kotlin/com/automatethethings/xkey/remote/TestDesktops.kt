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
package com.automatethethings.xkey.remote

/** The peer key [desktopOf] gives a test desktop unless told otherwise. */
internal const val TEST_PEER_KEY_HEX = "aa01"

/**
 * A [ConnectedDesktop] whose session is [sender]: a test stands in for one
 * connection's bound sender with a scripted or capturing one.
 */
internal fun desktopOf(
    sender: MessageSender,
    router: BidirectionalMessageRouter,
    peerKeyHex: String = TEST_PEER_KEY_HEX
): ConnectedDesktop =
    ConnectedDesktop(
        peerKeyHex,
        object : SessionSender {
            override suspend fun sendEncryptedMessage(data: ByteArray) = sender.sendEncryptedMessage(data)
        },
        router
    )
