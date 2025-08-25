package com.example.securecomm.crypto

import android.util.Log
import java.security.KeyPair
import java.security.PublicKey
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import com.example.securecomm.crypto.Frame
import com.example.securecomm.crypto.FrameType
import com.example.securecomm.crypto.FrameFlags

class SessionManager(private val cryptoManager: CryptoManager) {

    companion object {
        private const val TAG = "SessionManager"
        private const val MAX_SESSION_AGE_HOURS = 24
        private const val MAX_MESSAGES_PER_SESSION = 1000000
        private const val REPLAY_WINDOW_SIZE = 64
    }

    private val sessions = ConcurrentHashMap<Int, Session>()
    private val sessionCounter = AtomicInteger(Random.nextInt())
    private val deviceId = Random.nextInt()

    // Create a new session with a peer
    fun createSession(peerPublicKey: PublicKey): Session {
        val sessionId = sessionCounter.incrementAndGet()
        val session = Session(
            id = sessionId,
            peerPublicKey = peerPublicKey,
            createdAt = System.currentTimeMillis(),
            sendCounter = AtomicInteger(0),
            receiveCounter = AtomicInteger(0),
            replayWindow = ReplayWindow(REPLAY_WINDOW_SIZE)
        )

        sessions[sessionId] = session
        Log.d(TAG, "Created session $sessionId with peer")
        return session
    }

    // Get existing session or create new one
    fun getOrCreateSession(peerPublicKey: PublicKey): Session {
        val existingSession = sessions.values.find {
            it.peerPublicKey == peerPublicKey && !it.isExpired()
        }

        return existingSession ?: createSession(peerPublicKey)
    }

    // Perform key exchange and establish session keys
    fun establishSessionKeys(
        session: Session,
        ourKeyPair: KeyPair,
        peerPublicKey: PublicKey
    ): Boolean {
        return try {
            // Compute shared secret using ECDH
            val sharedSecret = cryptoManager.computeSharedSecret(
                ourKeyPair.private,
                peerPublicKey
            )

            // Generate salt from handshake transcript
            val salt = generateHandshakeSalt(session, ourKeyPair, peerPublicKey)

            // Derive session keys using HKDF
            val sessionKeys = cryptoManager.deriveSessionKeys(sharedSecret, salt)

            // Store session keys
            session.txKey = sessionKeys.kTx
            session.rxKey = sessionKeys.kRx
            session.isEstablished = true

            // Clean up shared secret
            cryptoManager.secureWipe(sharedSecret)

            Log.d(TAG, "Session keys established for session ${session.id}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish session keys", e)
            false
        }
    }

    // Encrypt message and return encrypted data (simplified - no Frame)
    fun encryptMessage(
        session: Session,
        message: String,
        destinationId: Int
    ): ByteArray? {
        if (!session.isEstablished) {
            Log.e(TAG, "Session ${session.id} not established")
            return null
        }

        return try {
            // Compress message if needed
            val messageBytes = message.toByteArray()
            val compressed = cryptoManager.compressData(messageBytes)
            val isCompressed = compressed.size < messageBytes.size

            // Prepare payload
            val payload = if (isCompressed) {
                Payload(
                    contentType = ContentType.TEXT,
                    isCompressed = true,
                    originalSize = messageBytes.size,
                    data = compressed
                )
            } else {
                Payload(
                    contentType = ContentType.TEXT,
                    isCompressed = false,
                    originalSize = messageBytes.size,
                    data = messageBytes
                )
            }

            // Encrypt payload directly (no Frame wrapper)
            encryptPayload(session, payload, destinationId, isCompressed)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt message", e)
            null
        }
    }

    // Decrypt frame and extract message (legacy - kept for backward compatibility)
    fun decryptMessage(session: Session, frame: Frame): String? {
        if (!session.isEstablished) {
            Log.e(TAG, "Session ${session.id} not established")
            return null
        }

        return try {
            // Check replay protection
            if (!session.replayWindow.checkAndAdd(frame.sequence)) {
                Log.w(TAG, "Replay attack detected for sequence ${frame.sequence}")
                return null
            }

            // Decrypt payload
            val aad = frame.getAAD()
            val rxKey = session.rxKey ?: throw IllegalStateException("Session not established")
            val decrypted = cryptoManager.decryptWithAAD(
                rxKey,
                frame.ciphertext,
                aad,
                frame.nonce
            ) ?: return null

            // Parse payload
            val payload = Payload.fromByteArray(decrypted) ?: return null

            // Decompress if needed
            val finalData = if (payload.isCompressed) {
                cryptoManager.decompressData(payload.data, payload.originalSize)
            } else {
                payload.data
            }

            String(finalData)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt message", e)
            null
        }
    }

    // Decrypt message from ByteArray (for received messages) - simplified approach
    fun decryptMessage(session: Session, encryptedData: ByteArray): String? {
        if (!session.isEstablished) {
            Log.e(TAG, "Session ${session.id} not established")
            return null
        }

        return try {
            // Try to parse as Frame first (legacy support)
            val frame = Frame.fromByteArray(encryptedData)
            if (frame != null) {
                return decryptMessage(session, frame)
            }

            // For new simplified approach, decrypt directly
            val rxKey = session.rxKey ?: throw IllegalStateException("Session not established")

            // Generate nonce from session info (simplified approach)
            val nonce = cryptoManager.generateNonce(session.id, deviceId, 0)

            // Decrypt the encrypted data directly
            val decrypted = cryptoManager.decryptWithAAD(
                rxKey,
                encryptedData,
                ByteArray(0), // Empty AAD for simplified decryption
                nonce
            ) ?: return null

            // Try to parse as Payload
            val payload = Payload.fromByteArray(decrypted)
            if (payload != null) {
                // Decompress if needed
                val finalData = if (payload.isCompressed) {
                    cryptoManager.decompressData(payload.data, payload.originalSize)
                } else {
                    payload.data
                }
                return String(finalData)
            }

            // If not a payload, return as plain text
            String(decrypted)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt message from ByteArray", e)
            null
        }
    }

    // Create frame with proper headers and encryption (legacy - kept for backward compatibility)
    private fun createFrame(
        session: Session,
        payload: Payload,
        destinationId: Int,
        isCompressed: Boolean
    ): Frame {
        val sequence = session.sendCounter.incrementAndGet()
        val nonce = cryptoManager.generateNonce(session.id, deviceId, sequence)

        // Prepare payload bytes
        val payloadBytes = payload.toByteArray()

        // Encrypt payload
        val aad = createAAD(session, destinationId, sequence, isCompressed)
        val txKey = session.txKey ?: throw IllegalStateException("Session not established")
        val encryptionResult = cryptoManager.encryptWithAAD(
            txKey,
            payloadBytes,
            aad,
            nonce
        )

        // Build frame
        return Frame(
            type = FrameType.DATA.value,
            flags = if (isCompressed) FrameFlags.COMPRESSED.value else 0,
            headerLength = Frame.FRAME_HEADER_SIZE.toByte(),
            sourceId = deviceId,
            destinationId = destinationId,
            sessionId = session.id,
            sequence = sequence,
            ttl = 32.toByte(),
            nonce = nonce,
            ciphertext = encryptionResult.ciphertext,
            tag = encryptionResult.iv // Using IV as tag for GCM
        )
    }

    // Encrypt payload directly (simplified approach - no Frame wrapper)
    private fun encryptPayload(
        session: Session,
        payload: Payload,
        destinationId: Int,
        isCompressed: Boolean
    ): ByteArray {
        val sequence = session.sendCounter.incrementAndGet()
        val nonce = cryptoManager.generateNonce(session.id, deviceId, sequence)

        // Prepare payload bytes
        val payloadBytes = payload.toByteArray()

        // Encrypt payload with minimal AAD
        val aad = createSimpleAAD(session, destinationId, isCompressed)
        val txKey = session.txKey ?: throw IllegalStateException("Session not established")
        val encryptionResult = cryptoManager.encryptWithAAD(
            txKey,
            payloadBytes,
            aad,
            nonce
        )

        // Return just the encrypted data (no Frame wrapper)
        return encryptionResult.ciphertext
    }

    // Create AAD (Associated Authenticated Data) - legacy approach
    private fun createAAD(
        session: Session,
        destinationId: Int,
        sequence: Int,
        isCompressed: Boolean
    ): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(20).order(java.nio.ByteOrder.BIG_ENDIAN)
        buffer.put(1) // version
        buffer.put(FrameType.DATA.value)
        buffer.put(if (isCompressed) FrameFlags.COMPRESSED.value else 0)
        buffer.put(Frame.FRAME_HEADER_SIZE.toByte())
        buffer.putInt(deviceId)
        buffer.putInt(destinationId)
        buffer.putInt(session.id)
        buffer.putInt(sequence)
        buffer.put(32) // TTL
        return buffer.array()
    }

    // Create simple AAD (Associated Authenticated Data) - simplified approach
    private fun createSimpleAAD(
        session: Session,
        destinationId: Int,
        isCompressed: Boolean
    ): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(12).order(java.nio.ByteOrder.BIG_ENDIAN)
        buffer.putInt(session.id)
        buffer.putInt(destinationId)
        buffer.putInt(if (isCompressed) 1 else 0)
        return buffer.array()
    }

    // Generate handshake salt
    private fun generateHandshakeSalt(
        session: Session,
        ourKeyPair: KeyPair,
        peerPublicKey: PublicKey
    ): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(64)
        buffer.putLong(session.createdAt)
        buffer.putInt(session.id)
        buffer.put(ourKeyPair.public.encoded)
        buffer.put(peerPublicKey.encoded)
        return buffer.array()
    }

    // Check if session needs rekeying
    fun needsRekey(session: Session): Boolean {
        return session.sendCounter.get() > MAX_MESSAGES_PER_SESSION ||
                System.currentTimeMillis() - session.createdAt > MAX_SESSION_AGE_HOURS * 60 * 60 * 1000
    }

    // Clean up expired sessions
    fun cleanupExpiredSessions() {
        val expiredSessions = sessions.values.filter { it.isExpired() }
        expiredSessions.forEach { session ->
            sessions.remove(session.id)
            // Clean up sensitive data
            session.txKey?.let { cryptoManager.secureWipe(it) }
            session.rxKey?.let { cryptoManager.secureWipe(it) }
            Log.d(TAG, "Cleaned up expired session ${session.id}")
        }
    }

    // Get session by ID
    fun getSession(sessionId: Int): Session? = sessions[sessionId]

    // Get all active sessions
    fun getActiveSessions(): List<Session> = sessions.values.filter { !it.isExpired() }
}

data class Session(
    val id: Int,
    val peerPublicKey: PublicKey,
    val createdAt: Long,
    val sendCounter: AtomicInteger,
    val receiveCounter: AtomicInteger,
    val replayWindow: ReplayWindow,
    var txKey: ByteArray? = null,
    var rxKey: ByteArray? = null,
    var isEstablished: Boolean = false
) {
    fun isExpired(): Boolean {
        return System.currentTimeMillis() - createdAt > 24 * 60 * 60 * 1000 // 24 hours
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Session
        return id == other.id
    }

    override fun hashCode(): Int = id
}

class ReplayWindow(private val windowSize: Int) {
    private val receivedSequences = mutableSetOf<Int>()
    private var highestSequence = -1

    fun checkAndAdd(sequence: Int): Boolean {
        // Check if sequence is within window
        if (sequence <= highestSequence - windowSize) {
            return false // Too old
        }

        // Check if already received
        if (receivedSequences.contains(sequence)) {
            return false // Duplicate
        }

        // Add to received set
        receivedSequences.add(sequence)

        // Update highest sequence
        if (sequence > highestSequence) {
            highestSequence = sequence
        }

        // Clean up old sequences outside window
        receivedSequences.removeIf { it <= highestSequence - windowSize }

        return true
    }
}

enum class ContentType(val value: Byte) {
    TEXT(1),
    BINARY(2),
    FILE(3),
    CONTROL(4)
}

data class Payload(
    val contentType: ContentType,
    val isCompressed: Boolean,
    val originalSize: Int,
    val data: ByteArray
) {
    fun toByteArray(): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(4 + data.size)
        buffer.put(contentType.value)
        buffer.put(if (isCompressed) 1 else 0)
        buffer.putShort(originalSize.toShort())
        buffer.put(data)
        return buffer.array()
    }

    companion object {
        fun fromByteArray(bytes: ByteArray): Payload? {
            return try {
                val buffer = java.nio.ByteBuffer.wrap(bytes)
                val contentType = ContentType.values().find { it.value == buffer.get() } ?: return null
                val isCompressed = buffer.get() == 1.toByte()
                val originalSize = buffer.short.toInt()
                val data = ByteArray(bytes.size - 4)
                buffer.get(data)
                Payload(contentType, isCompressed, originalSize, data)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Payload
        return contentType == other.contentType &&
                isCompressed == other.isCompressed &&
                originalSize == other.originalSize &&
                data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = contentType.hashCode()
        result = 31 * result + isCompressed.hashCode()
        result = 31 * result + originalSize
        result = 31 * result + data.contentHashCode()
        return result
    }
}
