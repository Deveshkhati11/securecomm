package com.example.securecomm.crypto

import android.util.Base64
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto utilities backed by BouncyCastle so they work on minSdk 24+.
 * - X25519: keygen + ECDH
 * - Ed25519: signatures
 * - HKDF-SHA256
 * - AES-GCM
 */
object CryptoUtils {

    // ------------------------------------------------------------------------
    // Provider & randomness
    // ------------------------------------------------------------------------
    private val rng = SecureRandom()

    init {
        // Register BC once (safe to call multiple times)
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    // ------------------------------------------------------------------------
    // Base64 (URL-safe, no padding) helpers
    // ------------------------------------------------------------------------
    fun b64(data: ByteArray): String =
        Base64.encodeToString(data, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)

    fun b64d(s: String): ByteArray =
        Base64.decode(s, Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)

    // ------------------------------------------------------------------------
    // X25519 (ECDH) - using BC lightweight API
    // ------------------------------------------------------------------------
    data class X25519KeyPair(val public: ByteArray, val private: ByteArray) // 32 bytes each

    fun generateX25519Identity(): X25519KeyPair {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(rng))
        val kp: AsymmetricCipherKeyPair = gen.generateKeyPair()
        val priv = kp.private as X25519PrivateKeyParameters
        val pub = kp.public as X25519PublicKeyParameters
        return X25519KeyPair(public = pub.encoded, private = priv.encoded)
    }

    /**
     * Compute ECDH shared secret (32 bytes) from my private (32) and their public (32).
     */
    fun computeSharedSecret(myPrivate: ByteArray, theirPublic: ByteArray): ByteArray {
        require(myPrivate.size == 32) { "X25519 private key must be 32 bytes" }
        require(theirPublic.size == 32) { "X25519 public key must be 32 bytes" }
        val priv = X25519PrivateKeyParameters(myPrivate, 0)
        val pub = X25519PublicKeyParameters(theirPublic, 0)
        val out = ByteArray(32)
        priv.generateSecret(pub, out, 0)
        return out
    }

    // ------------------------------------------------------------------------
    // Ed25519 (sign/verify) - BC lightweight API
    // ------------------------------------------------------------------------
    data class Ed25519KeyPair(val public: ByteArray, val private: ByteArray) // 32/32 bytes

    fun generateEd25519Identity(): Ed25519KeyPair {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(rng))
        val kp: AsymmetricCipherKeyPair = gen.generateKeyPair()
        val priv = kp.private as Ed25519PrivateKeyParameters
        val pub = kp.public as Ed25519PublicKeyParameters
        return Ed25519KeyPair(public = pub.encoded, private = priv.encoded)
    }

    fun ed25519Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    fun ed25519Verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(data, 0, data.size)
        return verifier.verifySignature(signature)
    }

    // ------------------------------------------------------------------------
    // HKDF-SHA256 (RFC 5869)
    // ------------------------------------------------------------------------
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hkdfExtract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val usedSalt = if (salt != null && salt.isNotEmpty()) salt else ByteArray(32) { 0 }
        return hmacSha256(usedSalt, ikm)
    }

    fun hkdfExpand(prk: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        var t = ByteArray(0)
        val okm = ArrayList<Byte>(outLen)
        var counter = 1
        while (okm.size < outLen) {
            val input = t + info + byteArrayOf(counter.toByte())
            t = hmacSha256(prk, input)
            okm.addAll(t.toList())
            counter++
        }
        return okm.take(outLen).toByteArray()
    }

    data class SessionKeys(
        val encKey: ByteArray,   // 32 bytes (AES-256)
        val extraKey: ByteArray? = null
    )

    /**
     * Derive a 32-byte encryption key from ECDH shared secret using HKDF-SHA256.
     * Salt should be random per session. `info` should bind identities/roles.
     */
    fun deriveSessionKeys(shared: ByteArray, salt: ByteArray, info: String): SessionKeys {
        val prk = hkdfExtract(salt, shared)
        val key = hkdfExpand(prk, info.toByteArray(), 32)
        return SessionKeys(encKey = key)
    }

    // ------------------------------------------------------------------------
    // AES-GCM (12-byte nonce, 16-byte tag)
    // ------------------------------------------------------------------------
    data class CipherMessage(
        val nonce: ByteArray,      // 12 bytes
        val ciphertext: ByteArray, // N bytes
        val tag: ByteArray         // 16 bytes (GCM tag)
    )

    fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): CipherMessage {
        require(key.size == 16 || key.size == 32) { "AES key must be 16 or 32 bytes" }
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        if (aad != null) cipher.updateAAD(aad)
        val out = cipher.doFinal(plaintext)
        val ct = out.copyOf(out.size - 16)
        val tag = out.copyOfRange(out.size - 16, out.size)
        return CipherMessage(nonce, ct, tag)
    }

    fun aesGcmDecrypt(key: ByteArray, msg: CipherMessage, aad: ByteArray? = null): ByteArray {
        require(key.size == 16 || key.size == 32) { "AES key must be 16 or 32 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, msg.nonce)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        if (aad != null) cipher.updateAAD(aad)
        val combined = msg.ciphertext + msg.tag
        return cipher.doFinal(combined)
    }

    // ------------------------------------------------------------------------
    // Helpers for packing/unpacking messages (Base64-url)
    // ------------------------------------------------------------------------
    data class PackedMessage(
        val nonceB64: String,
        val ctB64: String,
        val tagB64: String
    )

    fun pack(msg: CipherMessage): PackedMessage =
        PackedMessage(b64(msg.nonce), b64(msg.ciphertext), b64(msg.tag))

    fun unpack(p: PackedMessage): CipherMessage =
        CipherMessage(b64d(p.nonceB64), b64d(p.ctB64), b64d(p.tagB64))
}