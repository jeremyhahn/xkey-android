// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.remote

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.password.PasswordStoreLockedException
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.sync.SyncEngine
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/**
 * Phone-initiated (outbound) synchronization client.
 *
 * Sends the phone's local store contents to the laptop via the `remote.sync*`
 * methods and merges the laptop's reply (the `local` array) back into the local
 * stores. All gather/merge logic is delegated to [SyncEngine], which is shared
 * with the inbound `local.sync*` handlers so neither direction duplicates the
 * reconciliation logic.
 *
 * Wire contract: go-xkms `pkg/pairing/protocol_sync.go` (RemoteSync*Params /
 * RemoteSync*Result), handled on the desktop by the pairing Bridge.
 *
 * Requires an active paired connection: [messageSender] and [messageRouter]
 * come from the live transport (BLE / USB-AOA / TCP) for the connected desktop.
 */
class RemoteSyncClient(
    context: Context,
    private val messageSender: MessageSender,
    private val messageRouter: BidirectionalMessageRouter,
    private val requestTimeoutMs: Long = 30_000L
) {
    private val engine = SyncEngine(context.applicationContext)
    private val nextRequestId = AtomicLong(BASE_REQUEST_ID)

    /** Aggregate result of a sync run (items pushed to / pulled from the laptop). */
    data class SyncResult(
        val certsPushed: Int = 0,
        val certsPulled: Int = 0,
        val oathPushed: Int = 0,
        val oathPulled: Int = 0,
        val passwordsPushed: Int = 0,
        val passwordsPulled: Int = 0
    ) {
        val totalPulled: Int get() = certsPulled + oathPulled + passwordsPulled
        val totalPushed: Int get() = certsPushed + oathPushed + passwordsPushed
    }

    /** Runs a full bidirectional sync of all stores and records the sync time. */
    suspend fun syncAll(): SyncResult {
        val certs = syncTrustStore()
        val oath = syncOath()
        // A phone-initiated sync carries no unlocked vault, so with a factor
        // enrolled the password leg is refused before anything is sent; the
        // other stores still sync.
        val passwords = try {
            syncPasswords()
        } catch (e: PasswordStoreLockedException) {
            Log.i(TAG, "password vault is locked; passwords not synced")
            0 to 0
        }
        engine.markSynced()
        Log.i(TAG, "sync complete: pushed=${certs.first + oath.first + passwords.first} pulled=${certs.second + oath.second + passwords.second}")
        return SyncResult(
            certsPushed = certs.first, certsPulled = certs.second,
            oathPushed = oath.first, oathPulled = oath.second,
            passwordsPushed = passwords.first, passwordsPulled = passwords.second
        )
    }

    /** Pushes the phone's certificates and merges the laptop's. Returns (pushed, pulled). */
    suspend fun syncTrustStore(): Pair<Int, Int> {
        val mine = engine.gatherCertificates()
        val resp = sendRequest(MethodNames.REMOTE_SYNC_TRUST_STORE, JSONObject().put("certificates", mine))
        val merged = engine.mergeCertificates(resp.result?.optJSONArray("local") ?: JSONArray())
        return acceptedByPeer(resp) to merged.added
    }

    /** Pushes the phone's OATH credentials and merges the laptop's. Returns (pushed, pulled). */
    suspend fun syncOath(): Pair<Int, Int> {
        val mine = engine.gatherOath()
        val resp = sendRequest(MethodNames.REMOTE_SYNC_OATH, JSONObject().put("credentials", mine))
        val merged = engine.mergeOath(resp.result?.optJSONArray("local") ?: JSONArray())
        return acceptedByPeer(resp) to (merged.added + merged.updated)
    }

    /** Pushes the phone's passwords and merges the laptop's. Returns (pushed, pulled). */
    suspend fun syncPasswords(): Pair<Int, Int> {
        val mine = engine.gatherPasswords()
        val resp = sendRequest(MethodNames.REMOTE_SYNC_PASSWORDS, JSONObject().put("passwords", mine))
        val merged = engine.mergePasswords(resp.result?.optJSONArray("local") ?: JSONArray())
        return acceptedByPeer(resp) to (merged.added + merged.updated)
    }

    /**
     * How many of the offered items the desktop actually took, from the
     * `added`/`updated` counts every `remote.sync*` result carries. Counting
     * what was offered instead would report a push of items the desktop
     * skipped as already present.
     */
    private fun acceptedByPeer(response: Response): Int {
        val result = response.result ?: return 0
        return result.optInt("added") + result.optInt("updated")
    }

    private suspend fun sendRequest(method: String, params: JSONObject): Response {
        val id = nextRequestId.getAndIncrement()
        val request = Request(id, method, params)
        val deferred = CompletableDeferred<Response>()
        messageRouter.registerPendingResponse(id, deferred)
        try {
            Log.d(TAG, "Sending sync request: id=$id, method=$method")
            messageSender.sendEncryptedMessage(request.toJson())
            val response = withTimeout(requestTimeoutMs) { deferred.await() }
            if (response.isError()) {
                val error = response.error!!
                throw ProtocolException("Remote sync error: ${error.message}", errorCode = error.code)
            }
            return response
        } catch (e: TimeoutCancellationException) {
            throw ProtocolException("Sync request timed out: $method", errorCode = ErrorCodes.INTERNAL_ERROR)
        } finally {
            messageRouter.removePendingResponse(id)
        }
    }

    private companion object {
        const val TAG = "RemoteSyncClient"

        // Distinct from RemoteKeyClient's 1_000_000 base so outbound request IDs
        // from the two clients sharing one router never collide.
        const val BASE_REQUEST_ID = 2_000_000L
    }
}
