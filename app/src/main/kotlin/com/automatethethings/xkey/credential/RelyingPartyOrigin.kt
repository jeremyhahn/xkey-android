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
package com.automatethethings.xkey.credential

/**
 * The WebAuthn relationship between a ceremony's RP ID and the caller's origin.
 *
 * This matters only on the path where xKey authors the clientDataJSON itself.
 * There, the origin is one Android verified for the caller while the RP ID comes
 * from the request, and nothing otherwise forces the two to agree: xKey would
 * happily bind `https://example.com` into clientDataJSON while hashing
 * `attacker.test` into the signed authenticator data. A conformant relying party
 * rejects such a response, but an authenticator should not produce it.
 *
 * Deliberately pure and free of `android.*` so it is unit-testable on the JVM,
 * matching [UserVerificationCompliance].
 */
object RelyingPartyOrigin {

    /**
     * Reports whether [rpId] may be used for a ceremony on [origin], per the
     * WebAuthn Level 3 rule that the RP ID must equal the origin's effective
     * domain or be a registrable domain suffix of it.
     *
     * Only `https` origins qualify, with one exception carried by the spec:
     * `http://localhost` is treated as a secure context for development.
     *
     * @param rpId The relying party identifier from the request.
     * @param origin The origin Android verified for the calling application.
     */
    fun isRpIdValidForOrigin(rpId: String, origin: String): Boolean {
        if (rpId.isBlank()) return false
        val host = hostOf(origin) ?: return false
        val id = rpId.trimEnd('.').lowercase()
        return host == id || host.endsWith(".$id")
    }

    /**
     * Returns the lowercase host of [origin], or null when [origin] is not a
     * usable secure web origin. Parsing is done by hand rather than with
     * `java.net.URI` so the rules stay explicit and JVM-portable.
     */
    private fun hostOf(origin: String): String? {
        val secure = when {
            origin.startsWith("https://") -> origin.removePrefix("https://")
            origin.startsWith("http://") -> origin.removePrefix("http://").takeIf {
                it == "localhost" || it.startsWith("localhost:") || it.startsWith("localhost/")
            }
            else -> null
        } ?: return null

        val hostAndPort = secure.substringBefore('/').substringBefore('?').substringBefore('#')
        if (hostAndPort.isEmpty()) return null

        // Bracketed IPv6 literals have no registrable domain, so an RP ID can
        // never match one; reject rather than mangle them on the ':' below.
        if (hostAndPort.startsWith("[")) return null

        val host = hostAndPort.substringBefore(':').trimEnd('.').lowercase()
        return host.ifEmpty { null }
    }
}
