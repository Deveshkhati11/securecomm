package com.example.securecomm.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Legacy Frame data structure for complex message wrapping
 * NOTE: This is kept for backward compatibility. New implementations should use
 * the simplified approach: [fusion_id_len | fusion_id | encrypted_message]
 */
data class Frame(
    val version: Byte = 1,
    val type: Byte,
    val flags: Byte,
    val headerLength: Byte,
    val sourceId: Int,
    val destinationId: Int,
    val sessionId: Int,
    val sequence: Int,
    val ttl: Byte,
    val reserved: ByteArray = ByteArray(3),
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray
) {

    companion object {
        const val FRAME_HEADER_SIZE = 24
        const val NONCE_SIZE = 12
        const val TAG_SIZE = 16
        const val MAX_PAYLOAD_SIZE = 65535

        fun fromByteArray(data: ByteArray): Frame? {
            return try {
                if (data.size < FRAME_HEADER_SIZE + NONCE_SIZE + TAG_SIZE) {
                    return null
                }

                val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

                val version = buffer.get()
                val type = buffer.get()
                val flags = buffer.get()
                val headerLength = buffer.get()
                val sourceId = buffer.int
                val destinationId = buffer.int
                val sessionId = buffer.int
                val sequence = buffer.int
                val ttl = buffer.get()
                val reserved = ByteArray(3)
                buffer.get(reserved)

                val nonce = ByteArray(NONCE_SIZE)
                buffer.get(nonce)

                val ciphertextSize = data.size - FRAME_HEADER_SIZE - NONCE_SIZE - TAG_SIZE
                val ciphertext = ByteArray(ciphertextSize)
                buffer.get(ciphertext)

                val tag = ByteArray(TAG_SIZE)
                buffer.get(tag)

                Frame(
                    version = version,
                    type = type,
                    headerLength = headerLength,
                    flags = flags,
                    sourceId = sourceId,
                    destinationId = destinationId,
                    sessionId = sessionId,
                    sequence = sequence,
                    ttl = ttl,
                    reserved = reserved,
                    nonce = nonce,
                    ciphertext = ciphertext,
                    tag = tag
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    fun toByteArray(): ByteArray {
        val buffer = ByteBuffer.allocate(
            FRAME_HEADER_SIZE + nonce.size + ciphertext.size + tag.size
        ).order(ByteOrder.BIG_ENDIAN)

        buffer.put(version)
        buffer.put(type)
        buffer.put(flags)
        buffer.put(headerLength)
        buffer.putInt(sourceId)
        buffer.putInt(destinationId)
        buffer.putInt(sessionId)
        buffer.putInt(sequence)
        buffer.put(ttl)
        buffer.put(reserved)
        buffer.put(nonce)
        buffer.put(ciphertext)
        buffer.put(tag)

        return buffer.array()
    }

    fun getAAD(): ByteArray {
        val buffer = ByteBuffer.allocate(FRAME_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
        buffer.put(version)
        buffer.put(type)
        buffer.put(flags)
        buffer.put(headerLength)
        buffer.putInt(sourceId)
        buffer.putInt(destinationId)
        buffer.putInt(sessionId)
        buffer.putInt(sequence)
        buffer.put(ttl)
        buffer.put(reserved)
        return buffer.array()
    }

    fun isValid(): Boolean {
        return version == 1.toByte() &&
                headerLength == FRAME_HEADER_SIZE.toByte() &&
                nonce.size == NONCE_SIZE &&
                tag.size == TAG_SIZE &&
                ciphertext.size <= MAX_PAYLOAD_SIZE &&
                sequence >= 0 &&
                ttl > 0
    }
}

enum class FrameType(val value: Byte) {
    HANDSHAKE(1),
    DATA(2),
    ACK(3),
    REKEY(4),
    HEARTBEAT(5)
}

enum class FrameFlags(val value: Byte) {
    COMPRESSED(0x01),
    ENCRYPTED(0x02),
    SIGNED(0x04),
    FRAGMENTED(0x08),
    LAST_FRAGMENT(0x10)
}
