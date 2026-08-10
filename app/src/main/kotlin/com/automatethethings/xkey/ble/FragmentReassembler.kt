package com.automatethethings.xkey.ble

import android.util.Log
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap

/**
 * Reassembles fragmented BLE messages.
 *
 * BLE has a limited MTU (typically 20-512 bytes), so larger messages must be
 * fragmented. This class handles reassembly of fragmented messages according
 * to the xKey fragment protocol.
 *
 * Fragment header format (7 bytes):
 * - flags (1 byte): bit 0 = first fragment, bit 1 = last fragment
 * - sequence (2 bytes): sequence number within message (little-endian)
 * - total (2 bytes): total number of fragments (little-endian)
 * - length (2 bytes): payload length in this fragment (little-endian)
 *
 * Thread safety: This class is thread-safe.
 */
class FragmentReassembler {
    companion object {
        private const val TAG = "FragmentReassembler"

        // Header size in bytes
        const val HEADER_SIZE = 7

        // Flag bits
        const val FLAG_FIRST_FRAGMENT: Byte = 0x01
        const val FLAG_LAST_FRAGMENT: Byte = 0x02

        // Maximum message size (1 MB)
        private const val MAX_MESSAGE_SIZE = 1024 * 1024

        // Maximum fragments per message
        private const val MAX_FRAGMENTS = 1000

        // Timeout for incomplete messages (30 seconds)
        private const val TIMEOUT_MS = 30_000L
    }

    // Fragments indexed by sequence number
    private val fragments = ConcurrentHashMap<Int, ByteArray>()

    // Expected total number of fragments
    @Volatile
    private var expectedTotal = 0

    // Timestamp of first fragment received
    @Volatile
    private var startTime = 0L

    // Message ID for validation
    @Volatile
    private var currentMessageId: Int = 0

    /**
     * Adds a fragment to the reassembly buffer.
     *
     * @param data The raw fragment data including header
     * @return Complete reassembled message if all fragments received, null otherwise
     * @throws FragmentException if fragment is invalid
     */
    @Synchronized
    fun addFragment(data: ByteArray): ByteArray? {
        if (data.size < HEADER_SIZE) {
            throw FragmentException("Fragment too small: ${data.size} bytes")
        }

        val header = parseHeader(data)

        // Validate fragment
        validateFragment(header, data)

        // Check for timeout
        val now = System.currentTimeMillis()
        if (startTime > 0 && now - startTime > TIMEOUT_MS) {
            Log.w(TAG, "Fragment timeout, resetting reassembly")
            reset()
        }

        // Handle first fragment
        if (header.isFirst) {
            if (fragments.isNotEmpty()) {
                Log.w(TAG, "Received new first fragment, resetting previous incomplete message")
                reset()
            }
            startTime = now
            expectedTotal = header.total
            currentMessageId = header.sequence // Use sequence of first as message ID
        }

        // Validate total matches expected
        if (header.total != expectedTotal && expectedTotal > 0) {
            throw FragmentException("Fragment total mismatch: expected $expectedTotal, got ${header.total}")
        }

        // Store fragment payload
        val payload = data.copyOfRange(HEADER_SIZE, HEADER_SIZE + header.length)
        fragments[header.sequence] = payload

        Log.d(TAG, "Fragment ${header.sequence + 1}/${header.total} received (${payload.size} bytes)")

        // Check if complete
        if (header.isLast && fragments.size == expectedTotal) {
            return reassemble()
        }

        // Check if we have all fragments
        if (fragments.size == expectedTotal && expectedTotal > 0) {
            return reassemble()
        }

        return null
    }

    /**
     * Parses the fragment header.
     * Uses BIG_ENDIAN (network byte order) to match the Go implementation.
     */
    private fun parseHeader(data: ByteArray): FragmentHeader {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

        val flags = buffer.get()
        val sequence = buffer.getShort().toInt() and 0xFFFF
        val total = buffer.getShort().toInt() and 0xFFFF
        val length = buffer.getShort().toInt() and 0xFFFF

        return FragmentHeader(
            flags = flags,
            sequence = sequence,
            total = total,
            length = length,
            isFirst = (flags.toInt() and FLAG_FIRST_FRAGMENT.toInt()) != 0,
            isLast = (flags.toInt() and FLAG_LAST_FRAGMENT.toInt()) != 0
        )
    }

    /**
     * Validates a fragment.
     */
    private fun validateFragment(header: FragmentHeader, data: ByteArray) {
        // Check total is reasonable
        if (header.total <= 0 || header.total > MAX_FRAGMENTS) {
            throw FragmentException("Invalid fragment total: ${header.total}")
        }

        // Check sequence is valid
        if (header.sequence < 0 || header.sequence >= header.total) {
            throw FragmentException("Invalid sequence: ${header.sequence} of ${header.total}")
        }

        // Check length matches data
        if (HEADER_SIZE + header.length > data.size) {
            throw FragmentException("Length mismatch: header says ${header.length}, have ${data.size - HEADER_SIZE}")
        }

        // Check first/last flags are consistent
        if (header.isFirst && header.sequence != 0) {
            throw FragmentException("First flag set but sequence is ${header.sequence}")
        }
        if (header.isLast && header.sequence != header.total - 1) {
            throw FragmentException("Last flag set but sequence ${header.sequence} != total-1 (${header.total - 1})")
        }

        // Check for duplicate
        if (fragments.containsKey(header.sequence)) {
            Log.w(TAG, "Duplicate fragment ${header.sequence}, ignoring")
        }
    }

    /**
     * Reassembles all fragments into a complete message.
     */
    private fun reassemble(): ByteArray {
        // Calculate total size
        var totalSize = 0
        for (i in 0 until expectedTotal) {
            val fragment = fragments[i] ?: throw FragmentException("Missing fragment $i")
            totalSize += fragment.size
        }

        if (totalSize > MAX_MESSAGE_SIZE) {
            throw FragmentException("Reassembled message too large: $totalSize bytes")
        }

        // Reassemble
        val result = ByteBuffer.allocate(totalSize)
        for (i in 0 until expectedTotal) {
            result.put(fragments[i]!!)
        }

        Log.d(TAG, "Reassembled message: $totalSize bytes from $expectedTotal fragments")

        // Reset for next message
        reset()

        return result.array()
    }

    /**
     * Resets the reassembly state.
     */
    @Synchronized
    fun reset() {
        fragments.clear()
        expectedTotal = 0
        startTime = 0
        currentMessageId = 0
    }

    /**
     * Returns the number of fragments currently buffered.
     */
    fun getFragmentCount(): Int = fragments.size

    /**
     * Returns the expected total number of fragments.
     */
    fun getExpectedTotal(): Int = expectedTotal

    /**
     * Returns whether reassembly is in progress.
     */
    fun isInProgress(): Boolean = fragments.isNotEmpty()

    /**
     * Fragment header data.
     */
    private data class FragmentHeader(
        val flags: Byte,
        val sequence: Int,
        val total: Int,
        val length: Int,
        val isFirst: Boolean,
        val isLast: Boolean
    )
}

/**
 * Fragments messages for BLE transmission.
 *
 * This class splits large messages into fragments that fit within the BLE MTU.
 *
 * Thread safety: This class is thread-safe (stateless).
 */
class Fragmenter(
    private val maxPayloadSize: Int = DEFAULT_PAYLOAD_SIZE
) {
    companion object {
        private const val TAG = "Fragmenter"

        // Default payload size (MTU - ATT overhead - header)
        // MTU 247 - 3 ATT - 7 header = 237 bytes
        const val DEFAULT_PAYLOAD_SIZE = 237

        /**
         * Smallest payload a fragment may carry. Exposed so senders can check
         * their MTU arithmetic before constructing a [Fragmenter], which
         * otherwise throws.
         */
        const val MIN_PAYLOAD_SIZE = 20
    }

    init {
        require(maxPayloadSize >= MIN_PAYLOAD_SIZE) {
            "Payload size must be at least $MIN_PAYLOAD_SIZE bytes"
        }
    }

    /**
     * Fragments a message into BLE-sized chunks.
     *
     * @param data The message to fragment
     * @return List of fragments, each with header prepended
     */
    fun fragment(data: ByteArray): List<ByteArray> {
        if (data.isEmpty()) {
            return emptyList()
        }

        // Calculate number of fragments needed
        val numFragments = (data.size + maxPayloadSize - 1) / maxPayloadSize

        Log.d(TAG, "Fragmenting ${data.size} bytes into $numFragments fragment(s)")

        val fragments = mutableListOf<ByteArray>()
        var offset = 0
        var sequence = 0

        while (offset < data.size) {
            val payloadSize = minOf(maxPayloadSize, data.size - offset)
            val isFirst = sequence == 0
            val isLast = offset + payloadSize >= data.size

            val fragment = createFragment(
                data = data,
                offset = offset,
                length = payloadSize,
                sequence = sequence,
                total = numFragments,
                isFirst = isFirst,
                isLast = isLast
            )

            fragments.add(fragment)
            offset += payloadSize
            sequence++
        }

        return fragments
    }

    /**
     * Creates a single fragment with header.
     * Uses BIG_ENDIAN (network byte order) to match the Go implementation.
     */
    private fun createFragment(
        data: ByteArray,
        offset: Int,
        length: Int,
        sequence: Int,
        total: Int,
        isFirst: Boolean,
        isLast: Boolean
    ): ByteArray {
        var flags: Byte = 0
        if (isFirst) flags = (flags.toInt() or FragmentReassembler.FLAG_FIRST_FRAGMENT.toInt()).toByte()
        if (isLast) flags = (flags.toInt() or FragmentReassembler.FLAG_LAST_FRAGMENT.toInt()).toByte()

        val fragment = ByteBuffer.allocate(FragmentReassembler.HEADER_SIZE + length)
            .order(ByteOrder.BIG_ENDIAN)
            .put(flags)
            .putShort(sequence.toShort())
            .putShort(total.toShort())
            .putShort(length.toShort())
            .put(data, offset, length)

        return fragment.array()
    }
}

/**
 * Exception thrown for fragment reassembly errors.
 */
class FragmentException(message: String, cause: Throwable? = null) : Exception(message, cause)
