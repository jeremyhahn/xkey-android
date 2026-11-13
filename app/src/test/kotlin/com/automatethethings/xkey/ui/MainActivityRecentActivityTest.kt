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

import android.app.Application
import android.content.Context
import android.graphics.Rect
import android.os.Looper
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.children
import androidx.core.widget.NestedScrollView
import com.google.android.material.bottomnavigation.BottomNavigationView
import androidx.room.Room
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.concurrent.atomic.AtomicReference
import android.security.keystore.KeyGenParameterSpec
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

/**
 * A software stand-in for the AndroidKeyStore provider, which the JVM lacks:
 * enough for the encrypted preferences the home screen opens (AES keys by
 * alias).
 */
object FakeAndroidKeyStore {
    private const val NAME = "AndroidKeyStore"
    internal val keys: MutableMap<String, Key> = ConcurrentHashMap()

    fun install() {
        if (Security.getProvider(NAME) == null) Security.addProvider(FakeProvider())
    }

    class FakeProvider : Provider(NAME, 1.0, "Software AndroidKeyStore for JVM tests") {
        init {
            put("KeyStore.$NAME", Store::class.java.name)
            put("KeyGenerator.AES", AesGenerator::class.java.name)
        }
    }

    class Store : KeyStoreSpi() {
        override fun engineGetKey(alias: String, password: CharArray?): Key? = keys[alias]
        override fun engineGetCertificateChain(alias: String): Array<Certificate>? = null
        override fun engineGetCertificate(alias: String): Certificate? = null
        override fun engineGetCreationDate(alias: String): Date? = if (alias in keys) Date(0) else null
        override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<Certificate>?) {
            keys[alias] = key
        }
        override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<Certificate>?) =
            throw UnsupportedOperationException()
        override fun engineSetCertificateEntry(alias: String, cert: Certificate) =
            throw UnsupportedOperationException()
        override fun engineDeleteEntry(alias: String) {
            keys.remove(alias)
        }
        override fun engineAliases(): Enumeration<String> = Collections.enumeration(keys.keys.toList())
        override fun engineContainsAlias(alias: String): Boolean = alias in keys
        override fun engineSize(): Int = keys.size
        override fun engineIsKeyEntry(alias: String): Boolean = alias in keys
        override fun engineIsCertificateEntry(alias: String): Boolean = false
        override fun engineGetCertificateAlias(cert: Certificate): String? = null
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
    }

    class AesGenerator : KeyGeneratorSpi() {
        private var alias: String? = null
        private var bits = 256

        override fun engineInit(random: SecureRandom?) = Unit
        override fun engineInit(params: AlgorithmParameterSpec, random: SecureRandom?) {
            val spec = params as KeyGenParameterSpec
            alias = spec.keystoreAlias
            if (spec.keySize > 0) bits = spec.keySize
        }
        override fun engineInit(keysize: Int, random: SecureRandom?) {
            bits = keysize
        }
        override fun engineGenerateKey(): SecretKey {
            val key = KeyGenerator.getInstance("AES", "SunJCE").apply { init(bits) }.generateKey()
            alias?.let { keys[it] = key }
            return key
        }
    }
}

/**
 * Starts the home screen against an in-memory database holding audit entries
 * and reads the Recent Activity rows it shows.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class MainActivityRecentActivityTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private lateinit var database: XKeyDatabase

    /** A clock the test moves forward. */
    private val clock = object : Clock() {
        var now: Instant = Instant.parse("2026-11-12T12:00:00Z")
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = now
    }

    @Before
    fun setUp() {
        FakeAndroidKeyStore.install()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        install(database)
        MainActivity.recentActivityClock = clock
    }

    @After
    fun tearDown() {
        MainActivity.recentActivityClock = Clock.systemDefaultZone()
        XKeyDatabase.closeAndClear()
    }

    /** Makes [db] the instance [XKeyDatabase.getInstance] returns. */
    @Suppress("UNCHECKED_CAST")
    private fun install(db: XKeyDatabase) {
        val field = XKeyDatabase::class.java.getDeclaredField("instanceRef").apply { isAccessible = true }
        (field.get(null) as AtomicReference<XKeyDatabase?>).set(db)
    }

    private fun ago(duration: Duration) = clock.now.minus(duration).toEpochMilli()

    /**
     * The one way these tests read the Recent Activity rows: it opens [tab]
     * through the bottom navigation, as a user does, scrolls to the Audit Log
     * card and fails unless the section and every row are on screen with a
     * size. [alter] runs on the activity after the tab is opened, so a test
     * can break the screen and see this fail.
     */
    private fun shownRows(
        scenario: ActivityScenario<MainActivity>,
        tab: Int = R.id.nav_management,
        alter: (MainActivity) -> Unit = {},
    ): List<String> {
        scenario.onActivity { activity ->
            activity.findViewById<BottomNavigationView>(R.id.bottomNavigation).selectedItemId = tab
            alter(activity)
        }
        idleMainLooper()
        scenario.onActivity { activity ->
            val scroll = activity.findViewById<NestedScrollView>(R.id.nestedScrollView)
            val card = activity.findViewById<View>(R.id.cardAuditLog)
            val offset = Rect()
            scroll.offsetDescendantRectToMyCoords(card, offset)
            scroll.scrollTo(0, offset.top)
        }
        idleMainLooper()
        var texts = emptyList<String>()
        scenario.onActivity { activity ->
            listOf(R.id.containerManagement, R.id.cardAuditLog, R.id.layoutRecentActivity).forEach { id ->
                assertShown(activity.resources.getResourceEntryName(id), activity.findViewById(id))
            }
            val rows = activity.findViewById<LinearLayout>(R.id.layoutRecentActivityRows)
            assertShown("layoutRecentActivityRows", rows)
            assertTrue("Recent Activity shows no rows", rows.childCount > 0)
            texts = rows.children.map { row ->
                val text = (row as TextView).text.toString()
                assertShown("row \"$text\"", row)
                text
            }.toList()
        }
        return texts
    }

    private fun assertShown(name: String, view: View) {
        assertTrue("$name is not shown", view.isShown)
        assertTrue("$name has no size (${view.width}x${view.height})", view.width > 0 && view.height > 0)
    }

    /** Asserts that [shownRows] refuses to read rows the user cannot see. */
    private fun assertNotShown(
        scenario: ActivityScenario<MainActivity>,
        tab: Int = R.id.nav_management,
        alter: (MainActivity) -> Unit = {},
    ) {
        val error = assertThrows(AssertionError::class.java) { shownRows(scenario, tab, alter) }
        assertTrue(error.message, error.message.orEmpty().contains("is not shown"))
    }

    private fun idleMainLooper(duration: Duration = Duration.ZERO) {
        shadowOf(Looper.getMainLooper()).idleFor(duration)
        shadowOf(Looper.getMainLooper()).idle()
    }

    private fun pair(first: String, second: String) =
        context.getString(R.string.recent_activity_pair, first, second)

    @Test
    fun `the home screen shows recent audit rows with key labels and aging times`() {
        val keyId = "key-0123456789abcdef"
        runBlocking {
            database.keyDao().insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = "signing",
                    algorithm = "ES256",
                    label = "Work key",
                    keySizeBits = 256,
                    source = "generated"
                )
            )
            // Signing and key creation entries log the key id as the label.
            database.auditLogDao().insertAll(
                listOf(
                    AuditLogEntity(
                        timestamp = ago(Duration.ofMinutes(5)),
                        operationType = AuditOperationType.SIGNING_REQUEST,
                        keyId = keyId,
                        keyLabel = keyId,
                        success = true
                    ),
                    AuditLogEntity(
                        timestamp = ago(Duration.ofHours(2)),
                        operationType = AuditOperationType.KEY_CREATED,
                        keyId = "key-fedcba9876543210",
                        keyLabel = "key-fedcba9876543210",
                        success = false
                    )
                )
            )
        }

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            idleMainLooper()

            val succeeded = context.getString(R.string.recent_activity_succeeded)
            val failed = context.getString(R.string.recent_activity_failed)
            val signing = context.getString(R.string.audit_log_op_signing)
            val created = context.getString(R.string.audit_log_op_key_created)
            assertEquals(
                listOf(
                    pair(signing, "Work key"),
                    pair(succeeded, context.getString(R.string.recent_activity_minutes_ago, 5L)),
                    created,
                    pair(failed, context.getString(R.string.recent_activity_hours_ago, 2L))
                ),
                shownRows(scenario)
            )
            shownRows(scenario).forEach { text ->
                assertFalse(text, text.contains("key-0123456789abcdef"))
                assertFalse(text, text.contains("key-fedcba9876543210"))
            }

            // A minute passes with no audit change: the shown time moves on.
            clock.now = clock.now.plus(Duration.ofMinutes(1))
            idleMainLooper(Duration.ofMillis(RecentActivityRows.REFRESH_MILLIS))

            assertEquals(
                pair(succeeded, context.getString(R.string.recent_activity_minutes_ago, 6L)),
                shownRows(scenario)[1]
            )
        }
    }

    @Test
    fun `a key created without a label shows no raw key id on the home screen`() {
        val keyId = "key-0123456789abcdef"
        runBlocking {
            // A key generated without a label stores its key id as the label.
            database.keyDao().insert(
                KeyEntity(
                    keyId = keyId,
                    keyType = "signing",
                    algorithm = "ES256",
                    label = keyId,
                    keySizeBits = 256,
                    source = "generated"
                )
            )
            database.auditLogDao().insertAll(
                listOf(
                    AuditLogEntity(
                        timestamp = ago(Duration.ofMinutes(5)),
                        operationType = AuditOperationType.KEY_CREATED,
                        keyId = keyId,
                        keyLabel = keyId,
                        success = true
                    )
                )
            )
        }

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            idleMainLooper()

            assertEquals(
                listOf(
                    context.getString(R.string.audit_log_op_key_created),
                    pair(
                        context.getString(R.string.recent_activity_succeeded),
                        context.getString(R.string.recent_activity_minutes_ago, 5L)
                    )
                ),
                shownRows(scenario)
            )
            shownRows(scenario).forEach { text -> assertFalse(text, text.contains(keyId)) }
        }
    }

    @Test
    fun `rows the user cannot see never pass as shown`() {
        runBlocking {
            database.auditLogDao().insertAll(
                listOf(
                    AuditLogEntity(
                        timestamp = ago(Duration.ofMinutes(5)),
                        operationType = AuditOperationType.SIGNING_REQUEST,
                        keyId = null,
                        keyLabel = null,
                        success = true
                    )
                )
            )
        }

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            idleMainLooper()

            // On the Manage tab the row is on screen.
            assertEquals(context.getString(R.string.audit_log_op_signing), shownRows(scenario).first())
            // The Dashboard tab hides the Audit Log card's container.
            assertNotShown(scenario, tab = R.id.nav_dashboard)
            // A hidden Recent Activity section fails even on the Manage tab.
            assertNotShown(scenario) { activity ->
                activity.findViewById<View>(R.id.layoutRecentActivity).visibility = View.GONE
            }
        }
    }
}

/**
 * The unit tests run Robolectric offline (app/build.gradle.kts sets
 * robolectric.offline and points robolectric.dependency.dir at the one
 * android-all jar pinned as robolectricAndroidAll). A Robolectric test that
 * asks for another SDK makes Robolectric fetch that jar from Maven Central,
 * which fails in the offline CI container. This test fails first, locally.
 */
class RobolectricOfflinePinTest {

    private val moduleDir: java.io.File = java.io.File(requireNotNull(System.getProperty("user.dir")))

    /** The API level of the pinned jar: "14-robolectric-..." is Android 14, API 34. */
    private fun pinnedApi(): Int {
        val toml = java.io.File(moduleDir.parentFile, "gradle/libs.versions.toml").readText()
        val version = Regex("""(?m)^robolectricAndroidAll\s*=\s*"([^"]+)"""").find(toml)
            ?.groupValues?.get(1)
            ?: error("robolectricAndroidAll is missing from gradle/libs.versions.toml")
        return version.substringBefore('-').toInt() + 20
    }

    @Test
    fun `unit tests run Robolectric offline from the pinned android-all jar`() {
        assertEquals("true", System.getProperty("robolectric.offline"))
        val dir = java.io.File(
            System.getProperty("robolectric.dependency.dir")
                ?: error("robolectric.dependency.dir is not set"),
        )
        val jars = dir.listFiles().orEmpty().map { it.name }
        org.junit.Assert.assertTrue(
            "no android-all jar in $dir: $jars",
            jars.any { it.startsWith("android-all-instrumented-") && it.endsWith(".jar") },
        )
    }

    @Test
    fun `every Robolectric test asks for the pinned SDK`() {
        val api = pinnedApi()
        val sdkList = Regex("""@Config\([^)]*\bsdk\s*=\s*\[([^\]]*)]""")
        val offenders = moduleDir.resolve("src/test").walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.readText().contains("RobolectricTestRunner") }
            .flatMap { file ->
                sdkList.findAll(file.readText()).flatMap { match ->
                    match.groupValues[1].split(',').map { it.trim() }.filter { it.isNotEmpty() }
                        .filter { it.toIntOrNull() != api }
                        .map { "${file.name}: sdk = $it" }
                }
            }
            .toList()
        assertEquals("Robolectric tests on an SDK other than the pinned API $api", emptyList<String>(), offenders)
    }
}
