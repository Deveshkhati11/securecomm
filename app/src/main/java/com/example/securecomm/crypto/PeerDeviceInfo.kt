package com.example.mine.crypto

/**
 * Data class representing peer device information extracted from QR codes
 * Used for simplified routing: Phone → Fusion Node → encrypted message
 *
 * NOTE: With new simplified payload structure, only fusionNode and publicKeyBytes
 * are essential for message routing and decryption
 */
data class PeerDeviceInfo(
    val deviceId: String,           // Unique device identifier (legacy - not used in new payload)
    val deviceName: String,         // Human-readable device name (legacy - not used in new payload)
    val fusionNode: String,         // Fusion Node ID that the peer is connected to (ESSENTIAL)
    val connectionType: String,     // "bluetooth" or "wifi" (legacy - not used in new payload)
    val publicKeyBytes: ByteArray   // Raw public key bytes for cryptographic operations (ESSENTIAL)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PeerDeviceInfo

        if (deviceId != other.deviceId) return false
        if (deviceName != other.deviceName) return false
        if (fusionNode != other.fusionNode) return false
        if (connectionType != other.connectionType) return false
        if (!publicKeyBytes.contentEquals(other.publicKeyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceId.hashCode()
        result = 31 * result + deviceName.hashCode()
        result = 31 * result + fusionNode.hashCode()
        result = 31 * result + connectionType.hashCode()
        result = 31 * result + publicKeyBytes.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "PeerDeviceInfo(deviceId='$deviceId', deviceName='$deviceName', fusionNode='$fusionNode', connectionType='$connectionType')"
    }
}
