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
package com.automatethethings.xkey.e2e

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import java.io.File

/**
 * Utility methods for driving Chrome in UIAutomator2 E2E tests.
 */
object ChromeHelper {

    private const val CHROME_PACKAGE = "com.android.chrome"
    private const val DEFAULT_TIMEOUT = 10_000L

    /**
     * Launches Chrome via an ACTION_VIEW intent to the given URL.
     * This avoids needing to interact with the URL bar.
     */
    fun launchChromeToUrl(context: Context, device: UiDevice, url: String) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            setPackage(CHROME_PACKAGE)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        context.startActivity(intent)

        // Wait for Chrome to appear
        device.wait(Until.hasObject(By.pkg(CHROME_PACKAGE).depth(0)), DEFAULT_TIMEOUT)

        // Dismiss any first-run dialogs
        dismissChromeDialogs(device)
    }

    /**
     * Handles Chrome welcome/sync/sign-in prompts that appear on fresh emulators.
     * Attempts to dismiss common first-run dialogs.
     */
    fun dismissChromeDialogs(device: UiDevice) {
        // "Accept & continue" button (Terms of Service)
        val acceptButton = device.wait(
            Until.findObject(By.text("Accept & continue")),
            5_000L
        )
        acceptButton?.click()

        // "No thanks" for sync sign-in
        val noThanksButton = device.wait(
            Until.findObject(By.text("No thanks")),
            3_000L
        )
        noThanksButton?.click()

        // "No thanks" for notification prompt
        val noThanksNotif = device.wait(
            Until.findObject(By.text("No thanks")),
            2_000L
        )
        noThanksNotif?.click()

        // "Got it" for any remaining dialogs
        val gotItButton = device.wait(
            Until.findObject(By.text("Got it")),
            2_000L
        )
        gotItButton?.click()
    }

    /**
     * Waits for Chrome to finish loading the page by waiting for the
     * progress bar to disappear and content to become available.
     */
    fun waitForPageLoad(device: UiDevice, timeout: Long = 15_000L) {
        // Wait for Chrome's progress bar to disappear (indicates page loaded)
        device.wait(
            Until.gone(By.res(CHROME_PACKAGE, "progress")),
            timeout
        )
        // Small settle time for JavaScript rendering
        Thread.sleep(1_000L)
    }

    /**
     * Finds a web page element by its accessible text with timeout.
     * Chrome renders web content with accessibility nodes that can be found
     * by text content.
     *
     * @return The UiObject2 if found, null otherwise
     */
    fun findWebElement(
        device: UiDevice,
        text: String,
        timeout: Long = DEFAULT_TIMEOUT
    ) = device.wait(Until.findObject(By.text(text)), timeout)

    /**
     * Finds a web page element by text pattern (regex) with timeout.
     *
     * @return The UiObject2 if found, null otherwise
     */
    fun findWebElementByPattern(
        device: UiDevice,
        pattern: java.util.regex.Pattern,
        timeout: Long = DEFAULT_TIMEOUT
    ) = device.wait(Until.findObject(By.text(pattern)), timeout)

    /**
     * Finds a clickable element by its text and clicks it.
     *
     * @return true if the element was found and clicked
     */
    fun clickWebElement(
        device: UiDevice,
        text: String,
        timeout: Long = DEFAULT_TIMEOUT
    ): Boolean {
        val element = findWebElement(device, text, timeout)
        return if (element != null) {
            element.click()
            true
        } else {
            false
        }
    }

    /**
     * Saves a screenshot to /sdcard/Download/ for debugging failed tests.
     * Screenshots are named with the test name and timestamp.
     */
    fun takeScreenshotOnFailure(device: UiDevice, testName: String) {
        val downloadDir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_DOWNLOADS
        )
        val screenshotFile = File(
            downloadDir,
            "xkey-e2e-${testName}-${System.currentTimeMillis()}.png"
        )
        device.takeScreenshot(screenshotFile)
    }

    /**
     * Dumps the UI hierarchy to /sdcard/Download/ for debugging selectors.
     * Useful during test development to discover Chrome's accessibility tree.
     */
    fun dumpUiHierarchy(device: UiDevice, label: String) {
        val downloadDir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_DOWNLOADS
        )
        val dumpFile = File(
            downloadDir,
            "xkey-e2e-hierarchy-${label}-${System.currentTimeMillis()}.xml"
        )
        device.dumpWindowHierarchy(dumpFile)
    }
}
