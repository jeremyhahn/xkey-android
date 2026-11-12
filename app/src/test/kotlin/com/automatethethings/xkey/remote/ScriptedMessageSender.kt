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

import android.util.Log
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.every
import io.mockk.mockkStatic
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Test double for the paired-desktop transport shared by the `remote.*` client
 * tests.
 *
 * It parses each outbound [Request], records it for wire assertions, and feeds
 * the scripted reply straight back through the real
 * [BidirectionalMessageRouter] so request/response correlation by id is
 * exercised without a socket. A script returning `null` models a peer that
 * never answers, which drives the client's timeout path; a script that throws
 * models a dead link.
 */
class ScriptedMessageSender(
    private val router: BidirectionalMessageRouter,
    private var script: (Request) -> String? = { null }
) : MessageSender {

    /** Every request handed to the transport, in order. */
    val sent: MutableList<Request> = mutableListOf()

    /** The most recent outbound request. */
    val lastRequest: Request get() = sent.last()

    /** The peer confirmed on this transport's own connection, or null when none is. */
    var confirmedPeer: String? = null

    /** This transport's connection; replace it to model a reconnect. */
    var connection: Any = Any()

    override fun confirmedConnection(): ConfirmedConnection? =
        confirmedPeer?.let { ConfirmedConnection(it, connection) }

    /** Replaces the reply script for subsequent requests. */
    fun replyWith(script: (Request) -> String?) {
        this.script = script
    }

    /** Scripts a JSON-RPC success reply whose `result` is [resultJson]. */
    fun succeedWith(resultJson: String) {
        replyWith { request -> """{"id":${request.id},"result":$resultJson}""" }
    }

    /** Scripts a JSON-RPC error reply with [code] and [message]. */
    fun failWith(code: Int, message: String) {
        replyWith { request ->
            """{"id":${request.id},"error":{"code":$code,"message":"$message"}}"""
        }
    }

    /** Scripts a peer that never replies, so the caller must time out. */
    fun neverReply() {
        replyWith { null }
    }

    override suspend fun sendEncryptedMessage(data: ByteArray) {
        val request = Request.fromJson(data)
        sent += request
        script(request)?.let { router.processMessage(it.toByteArray(Charsets.UTF_8)) }
    }

    /** Sends on [connection] only while it is still this transport's confirmed one. */
    override suspend fun sendEncryptedMessageOn(connection: ConfirmedConnection, data: ByteArray) {
        if (!connection.sameAs(confirmedConnection())) throw ConnectionChangedException()
        sendEncryptedMessage(data)
    }
}

/**
 * One key shared with [peerPublicKeyHex] alone (selected peers), as the
 * phone's store holds it, for the tests that revoke it while a share is
 * pending. [makePrivate] and [removeGrant] are its revoke writers: each
 * commits its change the way the app's writers do.
 */
class SharedKeyStore(private val peerPublicKeyHex: String) {

    /** A fresh key id per store, so no two tests share one key's history. */
    val keyId = "pending-" + next.incrementAndGet()

    @Volatile var entity: KeyEntity? = KeyEntity(
        keyId = keyId,
        keyType = "signing",
        algorithm = "EC",
        label = "pending share",
        keySizeBits = 256,
        exportable = false,
        shareable = true,
        sharingPolicy = SharingPolicyType.SELECTED_PEERS,
        source = "local"
    )
        private set

    private val grants: MutableSet<Pair<String, String>> =
        ConcurrentHashMap.newKeySet<Pair<String, String>>().apply { add(keyId to peerPublicKeyHex) }

    val isShared: suspend (String, String) -> Boolean = { key, peer -> (key to peer) in grants }
    val current: suspend (String) -> KeyEntity? = { id -> entity?.takeIf { it.keyId == id } }

    /** The key is set to private. */
    suspend fun makePrivate() = revoke { entity = entity?.copy(shareable = false, sharingPolicy = SharingPolicyType.PRIVATE) }

    /** The peer's grant for the key is removed. */
    suspend fun removeGrant() = revoke { grants.remove(keyId to peerPublicKeyHex) }

    private suspend fun revoke(change: () -> Unit) {
        change()
    }

    private companion object {
        val next = AtomicInteger()
    }
}

/**
 * Stubs `android.util.Log`, which throws "not mocked" in JVM unit tests.
 *
 * Call from `@Before`; pair with `unmockkAll()` in `@After`.
 */
fun stubAndroidLog() {
    mockkStatic(Log::class)
    every { Log.d(any(), any()) } returns 0
    every { Log.i(any(), any()) } returns 0
    every { Log.w(any(), any<String>()) } returns 0
    every { Log.w(any(), any<String>(), any<Throwable>()) } returns 0
    every { Log.e(any(), any()) } returns 0
    every { Log.e(any(), any<String>(), any<Throwable>()) } returns 0
}
