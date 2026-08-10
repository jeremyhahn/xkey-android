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
package com.automatethethings.xkey.transport

/**
 * Exception thrown when a message exceeds the maximum frame size allowed by the
 * length-prefixed stream framing (see [StreamMessageFraming.MAX_MESSAGE_SIZE]).
 */
class MessageTooLargeException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
