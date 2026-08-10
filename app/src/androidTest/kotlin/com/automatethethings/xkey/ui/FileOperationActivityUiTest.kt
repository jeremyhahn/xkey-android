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
package com.automatethethings.xkey.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.text.format.Formatter
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented UI tests for [FileOperationActivity].
 *
 * The screen is a share target: it finishes immediately unless the intent
 * carries at least one URI, then builds a programmatic form whose visible cards
 * depend on the selected operation (sign and decrypt need a key, encrypt needs a
 * recipient, verify needs neither). These tests share real temporary files so
 * the file-info card has something to report, and seed a contact so the
 * recipient spinner has known content; both are cleaned up in @After.
 *
 * Tests cover:
 * - Launch behavior: finishes with no URI, survives one and several URIs
 * - File info card reporting the shared file names and sizes
 * - The operation selector actually switching which selector cards are visible
 * - The recipient spinner binding a seeded contact
 * - Result card staying hidden until an operation runs
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class FileOperationActivityUiTest {

    private lateinit var contactDao: ContactDao
    private lateinit var firstFile: File
    private lateinit var secondFile: File

    private val contactFingerprint = "fo${System.nanoTime()}"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        contactDao = XKeyDatabase.getInstance(context).contactDao()

        firstFile = File(context.cacheDir, FIRST_FILE_NAME).apply { writeText(FIRST_CONTENT) }
        secondFile = File(context.cacheDir, SECOND_FILE_NAME).apply { writeText(SECOND_CONTENT) }

        runBlocking {
            contactDao.insert(
                ContactEntity(
                    name = CONTACT_NAME,
                    publicKeyDer = ByteArray(32) { it.toByte() },
                    publicKeyFingerprint = contactFingerprint,
                    algorithm = CONTACT_ALGORITHM,
                    source = "file"
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking { contactDao.deleteByFingerprint(contactFingerprint) }
        firstFile.delete()
        secondFile.delete()
    }

    // -----------------------------------------------------------------
    // Launch behavior
    // -----------------------------------------------------------------

    /** An ACTION_SEND without EXTRA_STREAM yields no URIs, so onCreate finishes. */
    @Test
    fun activity_finishesWhenNoFileIsShared() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            setClass(context, FileOperationActivity::class.java)
        }

        val scenario = ActivityScenario.launch<FileOperationActivity>(intent)

        assertTrue(
            "Activity should finish when the share intent carries no URI",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    @Test
    fun activityLaunches_withFileUri() {
        val scenario = launchSingle()

        assertFalse(
            "FileOperationActivity should not be finishing with a valid file URI",
            withActivity(scenario) { it.isFinishing }
        )
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_title))
    }

    // -----------------------------------------------------------------
    // File info card
    // -----------------------------------------------------------------

    @Test
    fun fileInfoCard_reportsTheSharedFileNameAndSize() {
        val scenario = launchSingle()

        val expected = withActivity(scenario) {
            it.getString(
                R.string.file_operation_file_info,
                FIRST_FILE_NAME,
                Formatter.formatFileSize(it, FIRST_CONTENT.length.toLong())
            )
        }
        assertShownTextInTree(scenario, expected)
    }

    @Test
    fun fileInfoCard_listsEveryFileForAMultipleShare() {
        val scenario = launchMultiple()

        assertShownTextInTree(scenario, FIRST_FILE_NAME)
        assertShownTextInTree(scenario, SECOND_FILE_NAME)
    }

    // -----------------------------------------------------------------
    // Operation selector
    // -----------------------------------------------------------------

    @Test
    fun operationSelector_offersAllFourOperations() {
        val scenario = launchSingle()

        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_sign))
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_verify))
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_encrypt))
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_decrypt))
    }

    /** Sign is preselected, so the key selector is visible and no recipient is asked for. */
    @Test
    fun signOperation_showsKeySelectorAndHidesRecipientSelector() {
        val scenario = launchSingle()

        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_select_key))
        assertSelectorHidden(scenario, R.string.file_operation_select_recipient)
    }

    @Test
    fun encryptOperation_swapsTheKeySelectorForTheRecipientSelector() {
        val scenario = launchSingle()
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_select_key))

        clickClickableWithExactText(scenario, withString(scenario, R.string.file_operation_encrypt))

        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.file_operation_select_recipient)
        )
        assertSelectorHidden(scenario, R.string.file_operation_select_key)
    }

    @Test
    fun verifyOperation_hidesBothSelectors() {
        val scenario = launchSingle()
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_select_key))

        clickClickableWithExactText(scenario, withString(scenario, R.string.file_operation_verify))

        assertSelectorHidden(scenario, R.string.file_operation_select_key)
        assertSelectorHidden(scenario, R.string.file_operation_select_recipient)
    }

    @Test
    fun decryptOperation_bringsTheKeySelectorBack() {
        val scenario = launchSingle()

        clickClickableWithExactText(scenario, withString(scenario, R.string.file_operation_verify))
        assertSelectorHidden(scenario, R.string.file_operation_select_key)

        clickClickableWithExactText(scenario, withString(scenario, R.string.file_operation_decrypt))

        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_select_key))
        assertSelectorHidden(scenario, R.string.file_operation_select_recipient)
    }

    // -----------------------------------------------------------------
    // Recipient spinner
    // -----------------------------------------------------------------

    /**
     * The spinner shows its selected entry, which is the first contact by name.
     * The expectation is read from the DAO so contacts belonging to the device
     * cannot shift which entry lands in the collapsed spinner.
     */
    @Test
    fun recipientSpinner_bindsStoredContacts() {
        val scenario = launchSingle()
        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_select_key))

        clickClickableWithExactText(scenario, withString(scenario, R.string.file_operation_encrypt))

        val first = runBlocking { contactDao.getAll() }.first()
        assertShownTextInTree(scenario, "${first.name} (${first.algorithm})")
    }

    // -----------------------------------------------------------------
    // Result card
    // -----------------------------------------------------------------

    @Test
    fun processButton_isReadyAndNoResultIsShownBeforeAnOperationRuns() {
        val scenario = launchSingle()

        assertShownTextInTree(scenario, withString(scenario, R.string.file_operation_process))
        assertSelectorHidden(scenario, R.string.file_operation_sign_success)
        assertSelectorHidden(scenario, R.string.file_operation_verify_success)
    }

    // -----------------------------------------------------------------
    // Back navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launchSingle()

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launchSingle(): ActivityScenario<FileOperationActivity> {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uriFor(firstFile))
            setClass(context, FileOperationActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun launchMultiple(): ActivityScenario<FileOperationActivity> {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "text/plain"
            putParcelableArrayListExtra(
                Intent.EXTRA_STREAM,
                arrayListOf(uriFor(firstFile), uriFor(secondFile))
            )
            setClass(context, FileOperationActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun uriFor(file: File): Uri {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    private fun withString(
        scenario: ActivityScenario<FileOperationActivity>,
        resId: Int
    ): String = withActivity(scenario) { it.getString(resId) }

    /**
     * Asserts the label identified by [resId] exists in the tree but is not
     * visible, which is how this screen hides an unwanted selector card.
     */
    private fun assertSelectorHidden(
        scenario: ActivityScenario<FileOperationActivity>,
        resId: Int
    ) {
        val label = withString(scenario, resId)
        assertTrue(
            "'$label' should not be visible for the selected operation",
            awaitActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, label) == null
            }
        )
    }

    private companion object {
        const val FIRST_FILE_NAME = "xkey_ui_test_file.txt"
        const val SECOND_FILE_NAME = "xkey_ui_test_file_two.txt"
        const val FIRST_CONTENT = "test content"
        const val SECOND_CONTENT = "second test content"
        const val CONTACT_NAME = "UI FileOp Recipient"
        const val CONTACT_ALGORITHM = "EC P-256"
    }
}
