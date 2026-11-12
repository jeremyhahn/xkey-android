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

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ble.XKeyGattService
import com.automatethethings.xkey.protocol.RemoteBackendInfo
import com.automatethethings.xkey.protocol.RemoteKeyInfo
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/**
 * Keys held by the paired desktop's xkmsd backends, reached from the device
 * detail screen while a desktop session is up.
 *
 * Opening the screen lists the backends (`remote.listBackends`); choosing one
 * lists its keys (`remote.listKeys`); choosing a key shows its info and public
 * key, a sign-then-verify test on a fixed message and `remote.attestKey`. The
 * state logic lives in [DesktopKeysController]; this class only renders it.
 * The screen is opened for one desktop, named by its peer public key, and
 * sends nothing once the session is with any other.
 */
class DesktopKeysActivity : AppCompatActivity() {

    private var gattService: XKeyGattService? = null
    private var serviceBound = false
    private var running: Job? = null

    /** The last step launched, which Retry repeats. */
    private var lastStep: (suspend () -> Unit)? = null

    /** The client last adapted, so the same client is always the same source. */
    private var adapted: Pair<RemoteKeyClient, DesktopKeysSource>? = null

    private val controller by lazy {
        DesktopKeysController(
            peer = intent.getStringExtra(EXTRA_PEER_PUBLIC_KEY_HEX).orEmpty(),
            session = ::currentSession,
            onState = { render(it) }
        )
    }

    /** The service's desktop session now: its confirmed peer and its client. */
    private fun currentSession(): DesktopSession? {
        val service = gattService ?: return null
        val client = service.remoteKeyClient() ?: return null
        val source = adapted?.takeIf { it.first === client }?.second
            ?: DesktopKeysSource.of(client).also { adapted = client to it }
        return DesktopSession(service.getConnectedDevicePublicKeyHex(), source)
    }

    private lateinit var root: View
    private lateinit var progress: LinearProgressIndicator
    private lateinit var header: TextView
    private lateinit var message: TextView
    private lateinit var list: ListView
    private lateinit var detail: View
    private lateinit var detailInfo: TextView
    private lateinit var publicKeyHeader: TextView
    private lateinit var publicKeyText: TextView
    private lateinit var signTestButton: MaterialButton
    private lateinit var signTestText: TextView
    private lateinit var attestButton: MaterialButton
    private lateinit var attestationText: TextView

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            gattService = (binder as? XKeyGattService.LocalBinder)?.getService()
            serviceBound = true
            launch { controller.open() }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            gattService = null
            serviceBound = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_desktop_keys)

        root = findViewById(R.id.desktopKeysRoot)
        progress = findViewById(R.id.desktopKeysProgress)
        header = findViewById(R.id.textDesktopKeysHeader)
        message = findViewById(R.id.textDesktopKeysMessage)
        list = findViewById(R.id.listDesktopKeys)
        detail = findViewById(R.id.desktopKeyDetail)
        detailInfo = findViewById(R.id.textDesktopKeyInfo)
        publicKeyHeader = findViewById(R.id.textDesktopKeyPublicKeyHeader)
        publicKeyText = findViewById(R.id.textDesktopKeyPublicKey)
        signTestButton = findViewById(R.id.buttonDesktopKeySignTest)
        signTestText = findViewById(R.id.textDesktopKeySignTest)
        attestButton = findViewById(R.id.buttonDesktopKeyAttest)
        attestationText = findViewById(R.id.textDesktopKeyAttestation)

        val toolbar = findViewById<MaterialToolbar>(R.id.desktopKeysToolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.setTitle(R.string.desktop_keys_title)
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }

        signTestButton.setOnClickListener { launch { controller.signTest() } }
        attestButton.setOnClickListener { launch { controller.attest() } }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                running?.cancel()
                if (!controller.back()) finish()
            }
        })

        render(controller.state)
        serviceBound = bindService(
            Intent(this, XKeyGattService::class.java), serviceConnection, Context.BIND_AUTO_CREATE
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
    }

    /** Runs one controller step, replacing any step still in flight. */
    private fun launch(step: suspend () -> Unit) {
        running?.cancel()
        lastStep = step
        running = lifecycleScope.launch { step() }
    }

    private fun render(state: DesktopKeysState) {
        progress.visibility = if (state is DesktopKeysState.Loading) View.VISIBLE else View.GONE
        when (state) {
            is DesktopKeysState.Loading -> state.previous?.let(::renderContent) ?: showMessage(R.string.desktop_keys_loading)
            is DesktopKeysState.Failed -> {
                state.previous?.let(::renderContent) ?: showMessage(errorText(state.error))
                Snackbar.make(root, errorText(state.error), Snackbar.LENGTH_LONG)
                    .setAction(R.string.desktop_keys_retry) { lastStep?.let(::launch) }
                    .show()
            }
            else -> renderContent(state)
        }
        val busy = state is DesktopKeysState.Loading
        signTestButton.isEnabled = !busy
        attestButton.isEnabled = !busy
    }

    private fun renderContent(state: DesktopKeysState) {
        when (state) {
            DesktopKeysState.NoSession -> showMessage(R.string.desktop_keys_no_session)
            is DesktopKeysState.Backends -> showList(
                getString(R.string.desktop_keys_backends_header),
                R.string.desktop_keys_no_backends,
                state.backends.map(::backendRow)
            ) { position -> launch { controller.chooseBackend(state.backends[position]) } }
            is DesktopKeysState.Keys -> showList(
                getString(R.string.desktop_keys_keys_header, state.backend.name),
                R.string.desktop_keys_no_keys,
                state.keys.map(::keyRow)
            ) { position -> launch { controller.chooseKey(state.keys[position]) } }
            is DesktopKeysState.Detail -> showDetail(state)
            is DesktopKeysState.Loading, is DesktopKeysState.Failed -> Unit
        }
    }

    private fun showMessage(res: Int) = showMessage(getString(res))

    private fun showMessage(text: String) {
        header.visibility = View.GONE
        list.visibility = View.GONE
        detail.visibility = View.GONE
        message.text = text
        message.visibility = View.VISIBLE
    }

    private fun showList(title: String, emptyRes: Int, rows: List<Pair<String, String>>, onPick: (Int) -> Unit) {
        detail.visibility = View.GONE
        header.text = title
        header.visibility = View.VISIBLE
        if (rows.isEmpty()) {
            list.visibility = View.GONE
            message.setText(emptyRes)
            message.visibility = View.VISIBLE
            return
        }
        message.visibility = View.GONE
        list.adapter = RowAdapter(rows)
        list.setOnItemClickListener { _, _, position, _ -> onPick(position) }
        list.visibility = View.VISIBLE
    }

    private fun showDetail(state: DesktopKeysState.Detail) {
        header.visibility = View.GONE
        message.visibility = View.GONE
        list.visibility = View.GONE
        detail.visibility = View.VISIBLE

        val info = state.info
        val yes = getString(R.string.desktop_keys_yes)
        val no = getString(R.string.desktop_keys_no)
        detailInfo.text = listOf(
            R.string.desktop_keys_field_id to info.keyId,
            R.string.desktop_keys_field_label to info.label.ifEmpty { getString(R.string.desktop_keys_no_label) },
            R.string.desktop_keys_field_backend to info.backend,
            R.string.desktop_keys_field_algorithm to info.algorithm,
            R.string.desktop_keys_field_size to info.keySizeBits.toString(),
            R.string.desktop_keys_field_created to formatTime(info.createdAt),
            R.string.desktop_keys_field_hardware to (if (info.hardwareBacked) yes else no),
            R.string.desktop_keys_field_exportable to (if (info.exportable) yes else no)
        ).joinToString("\n") { (field, value) -> getString(R.string.desktop_keys_detail_value, getString(field), value) }

        publicKeyHeader.text = getString(R.string.desktop_keys_detail_public_key, state.publicKey.format)
        publicKeyText.text = state.publicKey.publicKey

        signTestButton.visibility = if (state.backend.signing) View.VISIBLE else View.GONE
        signTestText.visibility = if (state.signTest != null) View.VISIBLE else View.GONE
        state.signTest?.let {
            signTestText.text = getString(
                if (it.valid) R.string.desktop_keys_sign_test_valid else R.string.desktop_keys_sign_test_invalid,
                it.algorithm
            )
        }

        attestButton.visibility = if (state.backend.attestation) View.VISIBLE else View.GONE
        attestationText.visibility = if (state.attestation != null) View.VISIBLE else View.GONE
        state.attestation?.let {
            attestationText.text = getString(
                R.string.desktop_keys_attest_result,
                it.format, it.certificateCount, it.attestationDataBytes, it.nonce
            )
        }
    }

    private fun backendRow(backend: RemoteBackendInfo): Pair<String, String> = backend.name to getString(
        R.string.desktop_keys_backend_subtitle,
        backend.type,
        getString(if (backend.hardwareBacked) R.string.desktop_keys_hardware else R.string.desktop_keys_software)
    )

    private fun keyRow(key: RemoteKeyInfo): Pair<String, String> =
        key.label.ifEmpty { key.keyId } to getString(R.string.desktop_keys_key_subtitle, key.algorithm, key.keySizeBits)

    /** [seconds] since the epoch, or the raw value when it is not set. */
    private fun formatTime(seconds: Long): String =
        if (seconds <= 0) seconds.toString()
        else DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds * 1000))

    private fun errorText(error: DesktopKeyError): String = when (error.kind) {
        DesktopKeyError.Kind.NOT_CONNECTED -> getString(R.string.desktop_keys_error_not_connected)
        DesktopKeyError.Kind.KEY_NOT_FOUND -> getString(R.string.desktop_keys_error_key_not_found)
        DesktopKeyError.Kind.DENIED -> getString(R.string.desktop_keys_error_denied)
        DesktopKeyError.Kind.UNSUPPORTED -> getString(R.string.desktop_keys_error_unsupported)
        DesktopKeyError.Kind.ATTESTATION_FAILED -> getString(R.string.desktop_keys_error_attestation, error.detail)
        DesktopKeyError.Kind.REMOTE -> getString(R.string.desktop_keys_error_remote, error.detail)
        DesktopKeyError.Kind.TRANSPORT -> getString(R.string.desktop_keys_error_transport, error.detail)
    }

    /** Rows of title and subtitle in [R.layout.item_desktop_key]. */
    private inner class RowAdapter(rows: List<Pair<String, String>>) :
        ArrayAdapter<Pair<String, String>>(this, R.layout.item_desktop_key, rows) {
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val view = convertView
                ?: LayoutInflater.from(context).inflate(R.layout.item_desktop_key, parent, false)
            val (title, subtitle) = getItem(position)!!
            view.findViewById<TextView>(R.id.textDesktopKeyTitle).text = title
            view.findViewById<TextView>(R.id.textDesktopKeySubtitle).text = subtitle
            return view
        }
    }

    companion object {
        private const val EXTRA_PEER_PUBLIC_KEY_HEX = "peer_public_key_hex"

        /** Opens the desktop keys screen for the desktop whose peer public key is [peerPublicKeyHex]. */
        fun intent(context: Context, peerPublicKeyHex: String): Intent =
            Intent(context, DesktopKeysActivity::class.java)
                .putExtra(EXTRA_PEER_PUBLIC_KEY_HEX, peerPublicKeyHex)
    }
}
