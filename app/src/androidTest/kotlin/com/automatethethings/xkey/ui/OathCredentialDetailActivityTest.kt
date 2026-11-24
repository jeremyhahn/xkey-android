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

import android.content.ClipboardManager
import android.content.Context
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.matcher.ViewMatchers.withTagValue
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.`is`
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [OathCredentialDetailActivity], opened from the OATH
 * list's long-press Details.
 *
 * - A seeded TOTP shows every stored field, the current code and the seconds
 *   left in its period.
 * - A seeded HOTP shows the counter instead of a period and the RFC 4226 code
 *   at that counter; Copy copies it, advances the counter and shows the next
 *   code.
 * - Neither the shared secret nor its base32 form is ever on screen.
 * - The screen closes when its credential is deleted.
 *
 * Fields sit in a scroll view, partly below the fold, so they are read from
 * the view tree rather than required to be displayed. Seeded rows are deleted
 * in @After.
 */
@RunWith(AndroidJUnit4::class)
class OathCredentialDetailActivityTest {

    private val runId = System.nanoTime()
    private val totpAccount = "detail-totp-$runId@example.com"
    private val hotpAccount = "detail-hotp-$runId@example.com"

    private lateinit var context: Context
    private lateinit var repository: OathRepository
    private lateinit var oathDao: OathCredentialDao
    private val seeded = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        oathDao = XKeyDatabase.getInstance(context).oathCredentialDao()
        repository = OathRepository(oathDao, OathSecretManager())
    }

    @After
    fun tearDown() {
        runBlocking { seeded.forEach { repository.deleteCredential(it) } }
    }

    @Test
    fun totp_showsEveryFieldTheCodeAndTimeLeft() {
        val oathId = seed(totpAccount, type = "TOTP", algorithm = "SHA256", digits = 8, periodSeconds = 60)

        val scenario = launch(oathId)
        awaitText(scenario, totpAccount)

        assertShows(scenario, getString(R.string.oath_detail_issuer), ISSUER)
        assertShows(scenario, getString(R.string.oath_detail_account), totpAccount)
        assertShows(scenario, getString(R.string.oath_detail_type), "TOTP")
        assertShows(scenario, getString(R.string.oath_detail_algorithm), "SHA256")
        assertShows(scenario, getString(R.string.oath_detail_digits), "8")
        assertShows(scenario, getString(R.string.oath_detail_period), getString(R.string.oath_detail_period_value, 60))
        assertShows(scenario, getString(R.string.oath_detail_created))
        assertShows(scenario, getString(R.string.oath_detail_last_used), getString(R.string.oath_detail_never_used))
        assertShows(scenario, getString(R.string.oath_detail_use_count), getString(R.string.oath_detail_times_used, 0))
        assertShows(scenario, getString(R.string.oath_detail_source), "Local")
        assertShows(scenario, getString(R.string.oath_detail_security), getString(R.string.oath_detail_security_value))
        assertAbsent(scenario, getString(R.string.oath_detail_counter))

        scenario.onActivity { activity ->
            val decor = activity.window.decorView
            val code = decor.findViewWithTag<TextView>("code")
            assertTrue("8-digit code '${code.text}'", Regex("""\d{4} \d{4}""").matches(code.text))
            assertEquals("Code must stay on one line", 1, code.lineCount)
            val timeLeft = decor.findViewWithTag<TextView>("timeLeft")
            assertEquals(View.VISIBLE, timeLeft.visibility)
            val seconds = Regex("""\d+""").find(timeLeft.text)!!.value.toInt()
            assertTrue("Seconds left $seconds within the 60 s period", seconds in 1..60)
        }
        assertNoSecret(scenario)
    }

    @Test
    fun hotp_showsTheCounterAndItsCode_andCopyAdvancesIt() {
        val oathId = seed(hotpAccount, type = "HOTP", counter = 0L)

        val scenario = launch(oathId)
        awaitText(scenario, hotpAccount)

        assertShows(scenario, getString(R.string.oath_detail_type), "HOTP")
        assertShows(scenario, getString(R.string.oath_detail_counter), "0")
        assertShows(scenario, getString(R.string.oath_detail_hotp_hint))
        assertAbsent(scenario, getString(R.string.oath_detail_period))
        scenario.onActivity { activity ->
            val decor = activity.window.decorView
            // RFC 4226 appendix D, count 0.
            assertEquals("755 224", decor.findViewWithTag<TextView>("code").text.toString())
            assertEquals(View.GONE, decor.findViewWithTag<View>("timeLeft").visibility)
        }
        assertNoSecret(scenario)

        onView(withTagValue(`is`("copy"))).perform(scrollTo(), click())

        awaitCondition("Copy should advance the HOTP counter") {
            runBlocking { oathDao.getByOathId(oathId) }?.counter == 1L
        }
        scenario.onActivity { activity ->
            val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            assertEquals("755224", clipboard.primaryClip?.getItemAt(0)?.text?.toString())
        }
        // RFC 4226 appendix D, count 1.
        awaitText(scenario, "287 082")
        assertShows(scenario, getString(R.string.oath_detail_counter), "1")
        assertNoSecret(scenario)
    }

    @Test
    fun deletingTheCredential_closesTheScreen() {
        val oathId = seed(totpAccount, type = "TOTP")

        val scenario = launch(oathId)
        awaitText(scenario, totpAccount)

        runBlocking { repository.deleteCredential(oathId) }

        assertActivityDestroyed(scenario)
    }

    private fun launch(oathId: String): ActivityScenario<OathCredentialDetailActivity> =
        ActivityScenario.launch(OathCredentialDetailActivity.intent(context, oathId))

    private fun seed(
        account: String,
        type: String,
        algorithm: String = "SHA1",
        digits: Int = 6,
        periodSeconds: Int = 30,
        counter: Long = 0L
    ): String = runBlocking {
        repository.addCredential(
            issuer = ISSUER,
            accountName = account,
            secret = RAW_SECRET.toByteArray(Charsets.US_ASCII),
            type = type,
            algorithm = algorithm,
            digits = digits,
            periodSeconds = periodSeconds,
            counter = counter
        )
    }.also { seeded += it }

    private fun getString(res: Int, vararg args: Any): String = context.getString(res, *args)

    /** Every text in [texts] is in the screen's view tree, awaiting a refresh. */
    private fun assertShows(scenario: ActivityScenario<OathCredentialDetailActivity>, vararg texts: String) {
        texts.forEach { awaitText(scenario, it) }
    }

    private fun assertAbsent(scenario: ActivityScenario<OathCredentialDetailActivity>, text: String) {
        scenario.onActivity { activity ->
            val view = findShownTextView(activity.window.decorView, text)
            assertTrue("'$text' should not be shown", view == null)
        }
    }

    /** No text view holds the secret, raw or base32. */
    private fun assertNoSecret(scenario: ActivityScenario<OathCredentialDetailActivity>) {
        scenario.onActivity { activity ->
            val leaks = collectViews(activity.window.decorView) { view ->
                val text = (view as? TextView)?.text?.toString().orEmpty()
                text.contains(BASE32_SECRET, ignoreCase = true) || text.contains(RAW_SECRET)
            }
            assertTrue("The secret must never be on screen", leaks.isEmpty())
        }
    }

    private companion object {
        const val ISSUER = "AAA Detail Test"

        /** RFC 4226 test secret. */
        const val RAW_SECRET = "12345678901234567890"

        /** [RAW_SECRET] in base32, as an otpauth URI would carry it. */
        const val BASE32_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    }
}
