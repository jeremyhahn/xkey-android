/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ui

import android.Manifest
import android.app.Activity
import android.app.Application
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Looper
import android.view.View
import android.widget.Spinner
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.storage.entity.ContactEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.google.android.material.button.MaterialButton
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

/**
 * An operation waiting on the location-access answer across a recreation
 * runs with the key or recipient the user chose before the recreation, never
 * with whatever the rebuilt spinners show first; and if that key is gone,
 * nothing runs.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationAccessResumeSelectionTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private val capture = Uri.parse("content://media/external/images/media/7")

    @Before
    fun setUp() {
        db = TestDatabase()
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = folder.newFile("capture.png").apply { writeBytes(XmpFixtures.png()) }
            mimeType = "image/png"
        }
        shadowOf(RuntimeEnvironment.getApplication()).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        runBlocking {
            for (n in listOf("a", "b")) {
                db.database.keyDao().insert(
                    KeyEntity(
                        keyId = "key-$n",
                        keyType = "signing",
                        algorithm = "ES256",
                        label = "Signer $n",
                        keySizeBits = 256,
                        source = "generated"
                    )
                )
                db.database.contactDao().insert(
                    ContactEntity(
                        name = "Recipient $n",
                        publicKeyDer = ByteArray(8) { n[0].code.toByte() },
                        publicKeyFingerprint = "SHA256:$n",
                        algorithm = "ES256",
                        source = "import"
                    )
                )
            }
        }
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(5)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun signingKeys(activity: Activity) = field("signingKeys").get(activity) as List<KeyEntity>

    @Suppress("UNCHECKED_CAST")
    private fun contacts(activity: Activity) = field("contacts").get(activity) as List<ContactEntity>

    private fun spinner(activity: Activity, name: String) = field(name).get(activity) as Spinner

    /** Open the screen on [operation], pick entry 1 of [spinnerName], press Process, then recreate. */
    private fun chooseAndRecreate(
        operation: Int,
        spinnerName: String,
        beforeRecreate: (FileOperationActivity) -> Unit = {}
    ): Pair<ActivityController<FileOperationActivity>, Int> {
        val intent = Intent(Intent.ACTION_SEND).setType("image/png").putExtra(Intent.EXTRA_STREAM, capture)
        val controller = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup()
        val first = controller.get()
        idleUntil { signingKeys(first).size == 2 && contacts(first).size == 2 }
        field("selectedOperation").setInt(first, operation)
        FileOperationActivity::class.java.getDeclaredMethod("onOperationChanged").apply { isAccessible = true }
            .invoke(first)
        spinner(first, spinnerName).setSelection(1)
        (field("processButton").get(first) as MaterialButton).performClick()
        shadowOf(Looper.getMainLooper()).idle()
        val request = shadowOf(first).lastRequestedPermission
        assertNotNull("a fresh install is asked for location access", request)
        beforeRecreate(first)

        controller.recreate()
        val restored = controller.get()
        idleUntil { spinner(restored, spinnerName).adapter != null && signingKeys(restored).isNotEmpty() }
        shadowOf(Looper.getMainLooper()).idle()
        return controller to request!!.requestCode
    }

    private fun grant(activity: Activity, requestCode: Int) {
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        activity.onRequestPermissionsResult(
            requestCode,
            arrayOf(Manifest.permission.ACCESS_MEDIA_LOCATION),
            intArrayOf(PackageManager.PERMISSION_GRANTED)
        )
    }

    private fun keystoreOn(activity: Activity): KeystoreManager {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signWithAlgorithm(any(), any(), any()) } returns ByteArray(64) { 1 }
        field("keystoreManager").set(activity, keystore)
        return keystore
    }

    @Test
    fun `a sign resumed after a recreation signs with the key the user chose`() {
        val (controller, code) = chooseAndRecreate(OP_SIGN, "keySpinner")
        val restored = controller.get()
        // The first instance's choice: entry 1 of the same list, not the first key.
        val chosen = signingKeys(restored)[1].keyId
        val keystore = keystoreOn(restored)

        grant(restored, code)
        idleUntil { (field("resultCard").get(restored) as View).visibility == View.VISIBLE || runCatching {
            coVerify(atLeast = 1) { keystore.signWithAlgorithm(any(), any(), any()) }
        }.isSuccess }

        coVerify(exactly = 1) { keystore.signWithAlgorithm(chosen, any(), any()) }
    }

    @Test
    fun `an encrypt resumed after a recreation encrypts for the recipient the user chose`() {
        val (controller, code) = chooseAndRecreate(OP_ENCRYPT, "recipientSpinner")
        val restored = controller.get()
        val chosen = contacts(restored)[1].id

        grant(restored, code)
        val resultCard = field("resultCard").get(restored) as View
        idleUntil { resultCard.visibility == View.VISIBLE }

        val selected = spinner(restored, "recipientSpinner").selectedItemPosition
        assertEquals("the chosen recipient", chosen, contacts(restored)[selected].id)
    }

    @Test
    fun `a resumed sign whose chosen key is gone runs nothing`() {
        val (controller, code) = chooseAndRecreate(OP_SIGN, "keySpinner") { first ->
            val chosen = signingKeys(first)[1].keyId
            runBlocking { db.database.keyDao().deleteByKeyId(chosen) }
        }
        val restored = controller.get()
        val keystore = keystoreOn(restored)

        grant(restored, code)
        val resultCard = field("resultCard").get(restored) as View
        idleUntil { resultCard.visibility == View.VISIBLE }
        Thread.sleep(50)
        shadowOf(Looper.getMainLooper()).idle()

        coVerify(exactly = 0) { keystore.signWithAlgorithm(any(), any(), any()) }
        assertEquals("nothing waits on access", -1, field("operationAwaitingAccess").getInt(restored))
        assertTrue("the screen is free", (field("processButton").get(restored) as MaterialButton).isEnabled)
    }

    private companion object {
        const val OP_SIGN = 0
        const val OP_ENCRYPT = 2
    }
}
