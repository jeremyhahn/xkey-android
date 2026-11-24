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
package com.automatethethings.xkey.bootstrap

import okhttp3.Dns
import okhttp3.OkHttpClient
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

/**
 * A loopback HTTPS bootstrap endpoint that completes a real TLS handshake.
 *
 * The interceptor stand-in [StubBootstrapEndpoint] never reaches a trust
 * manager. This server does: it presents [chain] exactly as given (in order,
 * with no validation, so a test can serve a chain a hostile server would) and
 * proves possession of [privateKey] in the handshake, then answers each
 * HTTP/1.1 request with [status] and [body].
 *
 * The chain is served through an in-memory key manager rather than a PKCS12
 * KeyStore, because a KeyStore refuses a chain whose issuer names do not line
 * up, which is precisely the chain the hostile cases need.
 */
internal class TlsBootstrapServer(
    private val chain: List<X509Certificate>,
    private val privateKey: PrivateKey,
    private val status: Int = 200,
    private val body: ByteArray = ByteArray(0)
) : AutoCloseable {

    constructor(
        chain: List<X509Certificate>,
        privateKey: PrivateKey,
        body: String,
        status: Int = 200
    ) : this(chain, privateKey, status, body.toByteArray(Charsets.UTF_8))

    private val server: SSLServerSocket = SSLContext.getInstance("TLS").run {
        init(arrayOf<KeyManager>(ChainKeyManager()), null, null)
        serverSocketFactory.createServerSocket(0, BACKLOG, InetAddress.getLoopbackAddress())
            as SSLServerSocket
    }

    /** The loopback port the server listens on. */
    val port: Int = server.localPort

    private val acceptedCount = AtomicInteger()
    private val handshakeCount = AtomicInteger()
    private val requestLines = CopyOnWriteArrayList<String>()

    /** TCP connections accepted, whether or not the handshake completed. */
    val connections: Int get() = acceptedCount.get()

    /** TLS handshakes the server completed. */
    val handshakes: Int get() = handshakeCount.get()

    /** The HTTP request line of every request that reached the server. */
    val requests: List<String> get() = requestLines.toList()

    private val worker = Thread({ serve() }, "tls-bootstrap-server").apply {
        isDaemon = true
        start()
    }

    private fun serve() {
        while (!server.isClosed) {
            val socket = try {
                server.accept() as SSLSocket
            } catch (_: Exception) {
                return
            }
            acceptedCount.incrementAndGet()
            try {
                socket.use { handle(it) }
            } catch (_: Exception) {
                // A refused handshake or an aborted read ends this connection only.
            }
        }
    }

    private fun handle(socket: SSLSocket) {
        socket.soTimeout = SOCKET_TIMEOUT_MS
        socket.startHandshake()
        handshakeCount.incrementAndGet()
        val input = socket.getInputStream()
        val output = socket.getOutputStream()
        val head = readHead(input) ?: return
        requestLines.add(head.substringBefore("\r\n"))
        val header = "HTTP/1.1 $status ${if (status == 200) "OK" else "Error"}\r\n" +
            "Content-Type: application/x-pem-file\r\n" +
            "Content-Length: ${body.size}\r\n" +
            "Connection: close\r\n\r\n"
        output.write(header.toByteArray(Charsets.ISO_8859_1))
        output.write(body)
        output.flush()
    }

    /** Reads up to the blank line ending the request head, or null at end of stream. */
    private fun readHead(input: InputStream): String? {
        val buffer = ByteArrayOutputStream()
        while (true) {
            val next = input.read()
            if (next < 0) return null
            buffer.write(next)
            val size = buffer.size()
            if (size >= 4) {
                val bytes = buffer.toByteArray()
                if (bytes[size - 4] == CR && bytes[size - 3] == LF &&
                    bytes[size - 2] == CR && bytes[size - 1] == LF
                ) {
                    return String(bytes, Charsets.ISO_8859_1)
                }
            }
            if (size > MAX_HEAD_BYTES) return null
        }
    }

    override fun close() {
        runCatching { server.close() }
        worker.interrupt()
    }

    /** Serves [chain] and [privateKey] for any key type the key can sign for. */
    private inner class ChainKeyManager : X509ExtendedKeyManager() {
        private fun aliasFor(keyType: String?): String? =
            if (keyType == null || keyType.startsWith(privateKey.algorithm)) ALIAS else null

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

        override fun chooseClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            socket: Socket?
        ): String? = null

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
            aliasFor(keyType)?.let { arrayOf(it) }

        override fun chooseServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            socket: Socket?
        ): String? = aliasFor(keyType)

        override fun chooseEngineServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            engine: SSLEngine?
        ): String? = aliasFor(keyType)

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
            if (alias == ALIAS) chain.toTypedArray() else null

        override fun getPrivateKey(alias: String?): PrivateKey? =
            if (alias == ALIAS) privateKey else null
    }

    companion object {
        /** The name the clients dial; [loopbackClient] resolves it to the server. */
        const val HOST = "kms.example.test"

        private const val ALIAS = "bootstrap"
        private const val BACKLOG = 8
        private const val SOCKET_TIMEOUT_MS = 10_000
        private const val MAX_HEAD_BYTES = 16 * 1024
        private const val CR = '\r'.code.toByte()
        private const val LF = '\n'.code.toByte()

        /**
         * The client a test injects into `BootstrapClient`: every name resolves
         * to loopback, and both pinned clients keep that through `newBuilder()`.
         * It carries no interceptor, so every fetch completes a real handshake.
         */
        fun loopbackClient(timeoutSeconds: Long = 10): OkHttpClient = OkHttpClient.Builder()
            .dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> =
                    listOf(InetAddress.getLoopbackAddress())
            })
            .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .build()
    }
}
