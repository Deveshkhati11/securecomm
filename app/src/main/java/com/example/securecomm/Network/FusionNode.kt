package com.example.securecomm.Network

/**
 * Data class representing a Fusion Node device discovered via Bluetooth LE
 */
data class FusionNode(
    val name: String,
    val address: String,
    val rssi: Int,
    val deviceType: String,
    val isPaired: Boolean,
    val isConnected: Boolean
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as FusionNode
        return address == other.address
    }

    override fun hashCode(): Int = address.hashCode()

    override fun toString(): String {
        return "FusionNode(name='$name', address='$address', rssi=$rssi, deviceType='$deviceType', isPaired=$isPaired, isConnected=$isConnected)"
    }
}
