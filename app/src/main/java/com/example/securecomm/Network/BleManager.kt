package com.example.securecomm.Network

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

class BleManager(private val context: Context) {

    companion object {
        private const val TAG = "BleManager"

        // Fusion node service UUID
        private val FUSION_SERVICE_UUID = UUID.fromString("12345678-1234-1234-1234-123456789abc")

        // Characteristic UUIDs for communication
        private val MESSAGE_CHARACTERISTIC_UUID = UUID.fromString("87654321-4321-4321-4321-cba987654321")
        private val STATUS_CHARACTERISTIC_UUID = UUID.fromString("11111111-2222-3333-4444-555555555555")

        // BLE scan settings
        private const val SCAN_PERIOD_MS = 10000L
    }

    private val bluetoothManager: BluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager.adapter
    private val bluetoothLeScanner: BluetoothLeScanner? = bluetoothAdapter?.bluetoothLeScanner

    private var bluetoothGatt: BluetoothGatt? = null
    private var isConnected = false
    private var isScanning = false

    // State flows
    private val _discoveredDevices = MutableStateFlow<List<FusionNode>>(emptyList<FusionNode>())
    val discoveredDevices: StateFlow<List<FusionNode>> = _discoveredDevices.asStateFlow()

    private val _connectionStatus = MutableStateFlow<ConnectionStatus>(ConnectionStatus.Disconnected)
    val connectionStatus: StateFlow<ConnectionStatus> = _connectionStatus.asStateFlow()

    private val _receivedMessages = MutableStateFlow<List<ByteArray>>(emptyList<ByteArray>())
    val receivedMessages: StateFlow<List<ByteArray>> = _receivedMessages.asStateFlow()

    // Callback for GATT operations
    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.i(TAG, "Connected to GATT server")
                    isConnected = true
                    _connectionStatus.value = ConnectionStatus.Connected

                    if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                        gatt.discoverServices()
                    }
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.i(TAG, "Disconnected from GATT server")
                    isConnected = false
                    _connectionStatus.value = ConnectionStatus.Disconnected
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.i(TAG, "GATT services discovered")
                setupCharacteristicNotifications(gatt)
            } else {
                Log.e(TAG, "GATT service discovery failed: $status")
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            when (characteristic.uuid) {
                MESSAGE_CHARACTERISTIC_UUID -> {
                    Log.d(TAG, "Received message: ${value.size} bytes")
                    handleReceivedMessage(value)
                }
                STATUS_CHARACTERISTIC_UUID -> {
                    Log.d(TAG, "Status update: ${value.contentToString()}")
                }
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                Log.d(TAG, "Message sent successfully")
            } else {
                Log.e(TAG, "Failed to send message: $status")
            }
        }
    }

    // Modern BLE scan callback for Android 5.0+ (API 21+)
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            super.onScanResult(callbackType, result)

            val device = result.device
            val rssi = result.rssi
            val scanRecord = result.scanRecord

            if (isFusionNode(scanRecord?.bytes)) {
                val fusionNode = try {
                    if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                        FusionNode(
                            name = device.name ?: "Unknown Device",
                            address = device.address,
                            rssi = rssi,
                            deviceType = "Bluetooth LE",
                            isPaired = device.bondState == BluetoothDevice.BOND_BONDED,
                            isConnected = false
                        )
                    } else {
                        FusionNode(
                            name = "Unknown Device",
                            address = device.address,
                            rssi = rssi,
                            deviceType = "Bluetooth LE",
                            isPaired = false,
                            isConnected = false
                        )
                    }
                } catch (se: SecurityException) {
                    Log.e(TAG, "SecurityException accessing device info: ${se.message}")
                    FusionNode(
                        name = "Unknown Device",
                        address = device.address,
                        rssi = rssi,
                        deviceType = "Bluetooth LE",
                        isPaired = false,
                        isConnected = false
                    )
                }


                addDiscoveredDevice(fusionNode)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            super.onScanFailed(errorCode)
            Log.e(TAG, "BLE scan failed with error code: $errorCode")
            isScanning = false
        }
    }

    fun isBleSupported(): Boolean {
        return bluetoothLeScanner != null
    }

    fun isBleEnabled(): Boolean {
        return bluetoothAdapter?.isEnabled == true
    }

    fun startScan() {
        if (!isBleSupported() || !isBleEnabled()) {
            Log.e(TAG, "BLE not supported or not enabled")
            return
        }

        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            Log.e(TAG, "BLUETOOTH_SCAN permission not granted")
            return
        }

        if (isScanning) {
            Log.d(TAG, "Scan already in progress")
            return
        }

        _discoveredDevices.value = emptyList<FusionNode>()

        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED) {
            bluetoothLeScanner?.startScan(null, scanSettings, scanCallback)
            isScanning = true
            Log.d(TAG, "Started BLE scan for fusion nodes")
        }

        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            stopScan()
        }, SCAN_PERIOD_MS)
    }

    fun stopScan() {
        if (isScanning && bluetoothLeScanner != null) {
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED) {
                bluetoothLeScanner.stopScan(scanCallback)
                isScanning = false
                Log.d(TAG, "Stopped BLE scan")
            }
        }
    }

    private fun isFusionNode(scanRecord: ByteArray?): Boolean {
        if (scanRecord == null) return false
        val serviceUuidString = FUSION_SERVICE_UUID.toString()
        return scanRecord.any { it.toChar() == serviceUuidString.first() }
    }

    private fun addDiscoveredDevice(fusionNode: FusionNode) {
        val currentList: MutableList<FusionNode> = _discoveredDevices.value.toMutableList()
        val existingIndex = currentList.indexOfFirst { it.address == fusionNode.address }

        if (existingIndex >= 0) {
            currentList[existingIndex] = fusionNode
        } else {
            currentList.add(fusionNode)
        }

        _discoveredDevices.value = currentList
        Log.d(TAG, "Discovered fusion node: ${fusionNode.name} (${fusionNode.address})")
    }

    fun connectToDevice(fusionNode: FusionNode) {
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            Log.e(TAG, "BLUETOOTH_CONNECT permission not granted")
            return
        }

        _connectionStatus.value = ConnectionStatus.Connecting

        val adapter = bluetoothAdapter
        if (adapter == null) {
            Log.e(TAG, "Bluetooth adapter not available")
            _connectionStatus.value = ConnectionStatus.Error("Bluetooth adapter not available")
            return
        }

        val device = adapter.getRemoteDevice(fusionNode.address)

        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            bluetoothGatt = device.connectGatt(context, false, gattCallback)
            Log.d(TAG, "Attempting to connect to ${fusionNode.name}")
        }
    }

    fun disconnect() {
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            bluetoothGatt?.disconnect()
            bluetoothGatt?.close()
            bluetoothGatt = null
        }
        isConnected = false
        _connectionStatus.value = ConnectionStatus.Disconnected
        Log.d(TAG, "Disconnected from device")
    }

    fun sendMessage(message: ByteArray): Boolean {
        if (!isConnected || bluetoothGatt == null) {
            Log.e(TAG, "Not connected to any device")
            return false
        }

        val service = bluetoothGatt?.getService(FUSION_SERVICE_UUID)
        val characteristic = service?.getCharacteristic(MESSAGE_CHARACTERISTIC_UUID)

        if (characteristic == null) {
            Log.e(TAG, "Message characteristic not found")
            return false
        }

        characteristic.value = message

        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
            return bluetoothGatt?.writeCharacteristic(characteristic) == true
        }

        return false
    }

    private fun setupCharacteristicNotifications(gatt: BluetoothGatt) {
        val service = gatt.getService(FUSION_SERVICE_UUID)
        val messageCharacteristic = service?.getCharacteristic(MESSAGE_CHARACTERISTIC_UUID)
        val statusCharacteristic = service?.getCharacteristic(STATUS_CHARACTERISTIC_UUID)

        messageCharacteristic?.let { characteristic ->
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                gatt.setCharacteristicNotification(characteristic, true)
                val descriptor = characteristic.getDescriptor(
                    UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                )
                descriptor.value = byteArrayOf(0x01, 0x00)
                gatt.writeDescriptor(descriptor)
            }
        }

        statusCharacteristic?.let { characteristic ->
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED) {
                gatt.setCharacteristicNotification(characteristic, true)
                val descriptor = characteristic.getDescriptor(
                    UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                )
                descriptor.value = byteArrayOf(0x01, 0x00)
                gatt.writeDescriptor(descriptor)
            }
        }
    }

    private fun handleReceivedMessage(message: ByteArray) {
        Log.d(TAG, "BLE received message: ${message.size} bytes")

        // Store in local list
        val currentMessages: MutableList<ByteArray> = _receivedMessages.value.toMutableList()
        currentMessages.add(message)
        _receivedMessages.value = currentMessages

        // Forward to ViewModel for processing
        messageCallback?.onMessageReceived(message)
    }

    // Callback interface for message handling
    interface MessageCallback {
        fun onMessageReceived(message: ByteArray)
    }

    private var messageCallback: MessageCallback? = null

    fun setMessageCallback(callback: MessageCallback?) {
        messageCallback = callback
    }

    fun getConnectionStatus(): ConnectionStatus = _connectionStatus.value

    fun isConnected(): Boolean = isConnected

    fun isScanning(): Boolean = isScanning
}

sealed class ConnectionStatus {
    object Disconnected : ConnectionStatus()
    object Connecting : ConnectionStatus()
    object Connected : ConnectionStatus()
    data class Error(val message: String) : ConnectionStatus()
}
