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
package com.automatethethings.xkey.storage

import androidx.annotation.StringRes
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.crypto.KeyPresenceUnreadableException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.UserKeyKind
import java.security.KeyStore
import java.util.Base64

/**
 * What a screen's read of a key read (#255 review r7): the value, nothing
 * (no such key in the namespace read, an id both namespaces hold, or a
 * read that failed), or a refusal because a store the key could live in
 * cannot be read ([KeyPresenceUnreadableException]).
 */
sealed interface KeyRead<out T> {
    class Value<T>(val value: T) : KeyRead<T>
    object Unavailable : KeyRead<Nothing>
    object Unreadable : KeyRead<Nothing>
}

/**
 * The one choke point between a screen and a key read that can meet an
 * unreadable key store (#255 review r7): [read] runs here, and a
 * [KeyPresenceUnreadableException] out of it becomes [KeyRead.Unreadable],
 * a refusal the screen shows, never an exception out of its button listener
 * or coroutine, which would crash the app. Any other key-store failure is
 * [KeyRead.Unavailable]. Every ui/ read of a key through a resolver path
 * ([KeystoreManager.resolveKey] and every read built on it) goes through
 * this or a try that catches the exception.
 */
inline fun <T : Any> readRefusingUnreadable(read: () -> T?): KeyRead<T> =
    try {
        read()?.let { KeyRead.Value(it) } ?: KeyRead.Unavailable
    } catch (e: KeyPresenceUnreadableException) {
        KeyRead.Unreadable
    } catch (e: java.security.GeneralSecurityException) {
        KeyRead.Unavailable
    }

/**
 * The one choke point between a key read and a screen (#255 verify r3,
 * ruling 554): the read's value, or null after [refuse] is handed the
 * message the screen shows. An unreadable store is always refused
 * ([R.string.key_store_unreadable]); a read with no value is refused with
 * [unavailable], or skipped quietly when that is null (a key with no public
 * half, say). A caller never puts a stand-in (a key id, an empty key) in
 * place of a value it could not read.
 */
inline fun <T : Any> KeyRead<T>.orRefuse(@StringRes unavailable: Int?, refuse: (Int) -> Unit): T? =
    when (this) {
        is KeyRead.Value -> value
        KeyRead.Unavailable -> {
            unavailable?.let(refuse)
            null
        }
        KeyRead.Unreadable -> {
            refuse(R.string.key_store_unreadable)
            null
        }
    }

/**
 * A key's public key, DER-encoded, read by a screen ([readRefusingUnreadable]):
 * the co-sign screen's QRs name their key by this key's fingerprint.
 */
fun KeystoreManager.readOwnPublicKeyDer(keyId: String, kind: UserKeyKind): KeyRead<ByteArray> =
    readRefusingUnreadable { getPublicKeyDER(keyId, kind) }

/**
 * The one read of a key's public key by a screen (the key detail screen's
 * copy and the contacts screen's QR export): the key's one namespace
 * ([KeystoreManager.soleKind]) and its PEM, through [readRefusingUnreadable].
 * Unavailable is no public key (none in one namespace, or an id both hold);
 * Unreadable is a store the key could live in that cannot be read. The
 * screen takes it through [orRefuse], never an exception out of its button
 * or coroutine, and never a fallback to another namespace.
 *
 * The root and intermediate CA keys are listed by their raw Keystore
 * aliases ([CA_KEY_ALIASES]) and are no user key. A user key may hold such
 * an alias as its id, and then owns it (#255 verify r4): user-key ownership
 * is probed first, with its refusals, and the CA's certificate
 * ([caPublicKeyPem]) is read only when neither namespace holds the id. The
 * alias resolves in no namespace for any write, delete or private-key use.
 */
fun KeystoreManager.readOwnPublicKey(keyId: String): KeyRead<String> =
    readRefusingUnreadable {
        val kind = soleKind(keyId)
        when {
            kind != null -> getPublicKeyPEM(keyId, kind)
            keyId in CA_KEY_ALIASES && UserKeyKind.entries.none { holdsUserKey(keyId, it) } -> caPublicKeyPem(keyId)
            else -> null
        }
    }

/** The raw Keystore aliases of the CA keys a screen lists ([AndroidCA]). */
private val CA_KEY_ALIASES = setOf(AndroidCA.ROOT_CA_ALIAS, AndroidCA.INTERMEDIATE_CA_ALIAS)

/**
 * The PEM public key of the CA key under [alias], read from its Keystore
 * certificate only, or null when there is none or the Keystore cannot be
 * read. Laid out as [KeystoreManager.getPublicKeyPEM] lays out a user key's.
 */
private fun caPublicKeyPem(alias: String): String? {
    val der = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getCertificate(alias)?.publicKey?.encoded
    } catch (e: Exception) {
        null
    } ?: return null
    val body = Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n")
    return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
}

/**
 * What a key share may send for a key: its software material, or the public
 * key of its hardware key, or neither when the id holds no shareable key.
 */
class ShareableKey(val software: SoftwareKey?, val publicKeyPem: String?)

/**
 * The one read of a key a share sends (#255 review r4), for
 * `local.importSharedKey` and the key detail screen's desktop share alike.
 *
 * The namespace is resolved once ([KeystoreManager.exportKind]): a hardware
 * key shares its public key from either namespace, so a credential that
 * lives only under its credential alias shares like a general key. Both
 * reads run inside the use gate of that same kind ([KeyPolicyStore.withUsableKey]),
 * so a key whose delete was acknowledged is refused
 * ([KeyPolicyStore.KeyDeletedException]) and never read while its delete runs.
 * A general key beside a credential of its id shares its own key, a software
 * key too: the general namespace counts the software store (#255 review r6),
 * so the kind is never the credential's while a software key holds the id. A
 * software key read under a credential kind (stored after the kind was
 * resolved) is shared as neither.
 *
 * @param softwareKey reads the id's software key (a general key kept outside the Keystore)
 */
suspend fun KeyPolicyStore.readShareable(
    keyId: String,
    keystore: KeystoreManager,
    softwareKey: (String) -> SoftwareKey?
): ShareableKey {
    val kind = keystore.exportKind(keyId)
    return withUsableKey(keyId, kind) {
        val software = softwareKey(keyId)
        when {
            software != null && kind != UserKeyKind.GENERAL -> {
                software.material.fill(0)
                ShareableKey(null, null)
            }
            software != null -> ShareableKey(software, null)
            else -> ShareableKey(null, keystore.getPublicKeyPEM(keyId, kind))
        }
    }
}
