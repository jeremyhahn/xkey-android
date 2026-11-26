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
package com.automatethethings.xkey.sync

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ConnectedDesktop
import com.automatethethings.xkey.remote.RemoteSyncClient
import com.automatethethings.xkey.remote.SessionSender
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A phone-initiated sync ([RemoteSyncClient.syncAll]) end to end on the real
 * Room database and Keystore: the desktop is a [SessionSender] that parses
 * each outgoing request and answers it through the real
 * [BidirectionalMessageRouter] with a canned `remote.sync*` reply, so request
 * and reply correlation, the merge and the stores are all real.
 *
 * Running the same sync twice must add no second OATH row: the desktop's
 * items are stored under its ids and updated in place, and a password the
 * desktop holds at the same `updated_at` is kept, not rewritten.
 */
@RunWith(AndroidJUnit4::class)
class RemoteSyncRoundTripTest {

    private val suffix = System.nanoTime()
    private val totpId = "roundtrip-totp-$suffix"
    private val hotpId = "roundtrip-hotp-$suffix"
    private val passwordId = "roundtrip-pw-$suffix"

    private lateinit var context: Context
    private lateinit var db: XKeyDatabase
    private lateinit var router: BidirectionalMessageRouter
    private val sentMethods = mutableListOf<String>()

    /** The desktop's `local` arrays, by method, and its HOTP counter. */
    private var desktopHotpCounter = 4L

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        db = XKeyDatabase.getInstance(context)
        router = BidirectionalMessageRouter(
            RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager()
            )
        )
    }

    @After
    fun tearDown() = runBlocking<Unit> {
        db.oathCredentialDao().deleteByOathId(totpId)
        db.oathCredentialDao().deleteByOathId(hotpId)
        PasswordRepository(db.passwordDao()).delete(passwordId)
    }

    private fun desktopLocal(method: String): JSONArray = when (method) {
        "remote.syncOATH" -> JSONArray()
            .put(oath(totpId, "totp", 0))
            .put(oath(hotpId, "hotp", desktopHotpCounter))
        "remote.syncPasswords" -> JSONArray().put(
            JSONObject()
                .put("id", passwordId)
                .put("name", "Round Trip")
                .put("username", "user@example.com")
                .put("password", "desk-pw")
                .put("updated_at", "2026-01-01T00:00:00Z")
        )
        else -> JSONArray()
    }

    private fun oath(id: String, type: String, counter: Long) = JSONObject()
        .put("id", id)
        .put("name", id)
        .put("issuer", "Round Trip")
        .put("account_name", "user@example.com")
        .put("secret", "JBSWY3DPEHPK3PXP")
        .put("type", type)
        .put("algorithm", "SHA1")
        .put("digits", 6)
        .put("period", 30)
        .put("counter", counter)

    /** The desktop: every request is answered at once through the router, as a transport delivers a reply. */
    private val desktopSender = object : SessionSender {
        override suspend fun sendEncryptedMessage(data: ByteArray) {
            val request = Request.fromJson(data)
            sentMethods += request.method
            val result = JSONObject()
                .put("added", 0)
                .put("updated", 0)
                .put("local", desktopLocal(request.method))
            val reply = JSONObject().put("id", request.id.toJsonValue()).put("result", result)
            router.processMessage(reply.toString().toByteArray(Charsets.UTF_8))
        }
    }

    private fun client() = RemoteSyncClient(
        context,
        ConnectedDesktop("ab".repeat(32), desktopSender, router),
        requestTimeoutMs = 10_000L
    )

    @Test
    fun syncingTwiceAddsNoDuplicateOathRowsAndUpdatesCountersInPlace() = runBlocking {
        val dao = db.oathCredentialDao()
        val rowsBefore = dao.count()

        val first = client().syncAll()

        assertEquals(
            listOf("remote.syncTrustStore", "remote.syncOATH", "remote.syncPasswords"),
            sentMethods
        )
        assertEquals(2, first.oathPulled)
        assertEquals(1, first.passwordsPulled)
        assertEquals(rowsBefore + 2, dao.count())
        val hotpRow = dao.getByOathId(hotpId)!!
        assertEquals(4L, hotpRow.counter)

        desktopHotpCounter = 7L
        val second = client().syncAll()

        // Both credentials are updated in place under the desktop's ids, none added.
        assertEquals(2, second.oathPulled)
        assertEquals(rowsBefore + 2, dao.count())
        val updated = dao.getByOathId(hotpId)!!
        assertEquals(hotpRow.id, updated.id)
        assertEquals(hotpRow.createdAt, updated.createdAt)
        assertEquals(7L, updated.counter)
        // The desktop's password is the same age as the stored one: kept, not rewritten.
        assertEquals(0, second.passwordsPulled)
        assertEquals("desk-pw", PasswordRepository(db.passwordDao()).get(passwordId)?.password)
    }
}
