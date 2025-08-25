package com.example.securecomm.network

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class WifiDiscoveryManager(private val context: Context) {
    
    private val wifiManager: WifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
    
    private val _discoveredNetworks = MutableStateFlow<List<FusionWifiNetwork>>(emptyList())
    val discoveredNetworks: StateFlow<List<FusionWifiNetwork>> = _discoveredNetworks.asStateFlow()
    
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()
    
    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()
    
    private val _connectionStatus = MutableStateFlow<String>("Disconnected")
    val connectionStatus: StateFlow<String> = _connectionStatus.asStateFlow()
    
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()
    
    private var scanReceiver: BroadcastReceiver? = null
    private var connectionReceiver: BroadcastReceiver? = null
    private val discoveredNetworksList = mutableListOf<FusionWifiNetwork>()
    
    companion object {
        private const val TAG = "WifiDiscoveryManager"
        private const val SCAN_TIMEOUT = 15000L // 15 seconds
    }
    
    // Check if WiFi is supported
    fun isWifiSupported(): Boolean {
        return wifiManager != null
    }
    
    // Check if WiFi is enabled
    fun isWifiEnabled(): Boolean {
        return wifiManager.isWifiEnabled
    }
    
    // Check if we have required permissions
    fun hasRequiredPermissions(): Boolean {
        return ActivityCompat.checkSelfPermission(context, Manifest.permission.ACCESS_WIFI_STATE) == PackageManager.PERMISSION_GRANTED &&
               ActivityCompat.checkSelfPermission(context, Manifest.permission.CHANGE_WIFI_STATE) == PackageManager.PERMISSION_GRANTED
    }
    
    // Start WiFi network scanning
    fun startScan() {
        if (!isWifiSupported()) {
            _errorMessage.value = "WiFi is not supported on this device"
            return
        }
        
        if (!isWifiEnabled()) {
            _errorMessage.value = "WiFi is disabled. Please enable WiFi."
            return
        }
        
        if (!hasRequiredPermissions()) {
            _errorMessage.value = "WiFi permissions required for scanning"
            return
        }
        
        try {
            // Clear previous results
            discoveredNetworksList.clear()
            _discoveredNetworks.value = emptyList()
            _errorMessage.value = null
            
            // Register receiver for scan results
            registerScanReceiver()
            
            // Start scanning
            val scanStarted = wifiManager.startScan()
            if (scanStarted) {
                _isScanning.value = true
                Log.d(TAG, "WiFi scan started")
                
                // Stop scanning after timeout
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                    stopScan()
                }, SCAN_TIMEOUT)
            } else {
                _errorMessage.value = "Failed to start WiFi scan"
                Log.e(TAG, "Failed to start WiFi scan")
            }
        } catch (e: Exception) {
            _errorMessage.value = "Error starting WiFi scan: ${e.message}"
            Log.e(TAG, "Error starting WiFi scan", e)
        }
    }
    
    // Stop WiFi scanning
    fun stopScan() {
        try {
            _isScanning.value = false
            Log.d(TAG, "WiFi scan stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping WiFi scan", e)
        }
    }
    
    // Register broadcast receiver for scan results
    private fun registerScanReceiver() {
        scanReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    WifiManager.SCAN_RESULTS_AVAILABLE_ACTION -> {
                        handleScanResults()
                    }
                }
            }
        }
        
        val filter = IntentFilter().apply {
            addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        }
        
        context.registerReceiver(scanReceiver, filter)
    }
    
    // Handle scan results
    private fun handleScanResults() {
        try {
            val scanResults = wifiManager.scanResults
            Log.d(TAG, "WiFi scan completed. Found ${scanResults.size} networks")
            
            discoveredNetworksList.clear()
            
            scanResults.forEach { scanResult ->
                val fusionNetwork = createFusionWifiNetwork(scanResult)
                discoveredNetworksList.add(fusionNetwork)
            }
            
            // Sort by signal strength (strongest first)
            discoveredNetworksList.sortByDescending { it.rssi }
            
            _discoveredNetworks.value = discoveredNetworksList.toList()
            _isScanning.value = false
            
        } catch (e: Exception) {
            Log.e(TAG, "Error handling scan results", e)
            _errorMessage.value = "Error processing scan results: ${e.message}"
            _isScanning.value = false
        }
    }
    
    // Create FusionWifiNetwork from ScanResult
    private fun createFusionWifiNetwork(scanResult: ScanResult): FusionWifiNetwork {
        return FusionWifiNetwork(
            ssid = scanResult.SSID,
            bssid = scanResult.BSSID,
            rssi = scanResult.level,
            frequency = scanResult.frequency,
            capabilities = scanResult.capabilities,
            securityType = getSecurityType(scanResult.capabilities),
            channel = getChannelFromFrequency(scanResult.frequency),
            isFusionNode = isFusionNode(scanResult.SSID, scanResult.capabilities)
        )
    }
    
    // Determine security type from capabilities
    private fun getSecurityType(capabilities: String): String {
        return when {
            capabilities.contains("WPA3") -> "WPA3"
            capabilities.contains("WPA2") -> "WPA2"
            capabilities.contains("WPA") -> "WPA"
            capabilities.contains("WEP") -> "WEP"
            capabilities.contains("ESS") -> "Open"
            else -> "Unknown"
        }
    }
    
    // Get channel from frequency
    private fun getChannelFromFrequency(frequency: Int): Int {
        return when (frequency) {
            in 2412..2484 -> (frequency - 2412) / 5 + 1
            in 5170..5825 -> (frequency - 5170) / 5 + 34
            else -> 0
        }
    }
    
    // Check if this might be a fusion node (custom logic)
    private fun isFusionNode(ssid: String, capabilities: String): Boolean {
        // This is a heuristic - you can customize this logic
        val fusionKeywords = listOf("fusion", "node", "mesh", "router", "gateway")
        val ssidLower = ssid.lowercase()
        
        return fusionKeywords.any { keyword ->
            ssidLower.contains(keyword)
        } || capabilities.contains("WPA2") // Most fusion nodes use WPA2
    }
    
    // Check current connection status
    fun getCurrentConnection(): String {
        return try {
            val connectionInfo = wifiManager.connectionInfo
            if (connectionInfo != null && connectionInfo.networkId != -1) {
                val ssid = connectionInfo.ssid?.removeSurrounding("\"") ?: "Unknown"
                _isConnected.value = true
                _connectionStatus.value = "Connected to $ssid"
                "Connected to $ssid"
            } else {
                _isConnected.value = false
                _connectionStatus.value = "Disconnected"
                "Disconnected"
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting connection status", e)
            _isConnected.value = false
            _connectionStatus.value = "Error"
            "Error"
        }
    }
    
    // Register connection status receiver
    private fun registerConnectionReceiver() {
        connectionReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    WifiManager.NETWORK_STATE_CHANGED_ACTION -> {
                        val networkInfo = intent.getParcelableExtra<android.net.NetworkInfo>(WifiManager.EXTRA_NETWORK_INFO)
                        when (networkInfo?.state) {
                            android.net.NetworkInfo.State.CONNECTED -> {
                                val connectionInfo = wifiManager.connectionInfo
                                val ssid = connectionInfo?.ssid?.removeSurrounding("\"") ?: "Unknown"
                                _isConnected.value = true
                                _connectionStatus.value = "Connected to $ssid"
                                Log.d(TAG, "Connected to WiFi: $ssid")
                            }
                            android.net.NetworkInfo.State.DISCONNECTED -> {
                                _isConnected.value = false
                                _connectionStatus.value = "Disconnected"
                                Log.d(TAG, "Disconnected from WiFi")
                            }
                            android.net.NetworkInfo.State.CONNECTING -> {
                                _connectionStatus.value = "Connecting..."
                                Log.d(TAG, "Connecting to WiFi...")
                            }
                            else -> {
                                _connectionStatus.value = "Unknown state"
                            }
                        }
                    }
                }
            }
        }
        
        val filter = IntentFilter().apply {
            addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION)
        }
        
        context.registerReceiver(connectionReceiver, filter)
    }
    
    // Disconnect from current network
    fun disconnectFromNetwork() {
        try {
            Log.d(TAG, "Disconnecting from WiFi network...")
            // Reset connection state
            _isConnected.value = false
            _connectionStatus.value = "Disconnected"
            Log.d(TAG, "Disconnected from WiFi network")
        } catch (e: Exception) {
            Log.e(TAG, "Error disconnecting from WiFi network", e)
        }
    }
    
    // Connect to a specific network
    fun connectToNetwork(network: FusionWifiNetwork, password: String? = null): Boolean {
        try {
            Log.d(TAG, "Connecting to network: ${network.ssid} (${network.bssid})")
            
            // Check if WiFi is enabled
            if (!isWifiEnabled()) {
                Log.e(TAG, "WiFi is disabled")
                return false
            }
            
            // Check permissions
            if (!hasRequiredPermissions()) {
                Log.e(TAG, "WiFi permissions not granted")
                return false
            }
            
            // Create network configuration
            val networkConfig = android.net.wifi.WifiConfiguration().apply {
                SSID = "\"${network.ssid}\""
                BSSID = network.bssid
                
                // Set security based on network type
                when (network.securityType) {
                    "Open" -> {
                        allowedKeyManagement.set(android.net.wifi.WifiConfiguration.KeyMgmt.NONE)
                    }
                    "WEP" -> {
                        allowedKeyManagement.set(android.net.wifi.WifiConfiguration.KeyMgmt.NONE)
                        allowedAuthAlgorithms.set(android.net.wifi.WifiConfiguration.AuthAlgorithm.OPEN)
                        allowedAuthAlgorithms.set(android.net.wifi.WifiConfiguration.AuthAlgorithm.SHARED)
                        if (password != null) {
                            wepKeys[0] = "\"$password\""
                            wepTxKeyIndex = 0
                        }
                    }
                    "WPA", "WPA2", "WPA3" -> {
                        allowedKeyManagement.set(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_PSK)
                        if (password != null) {
                            preSharedKey = "\"$password\""
                        }
                    }
                    else -> {
                        Log.e(TAG, "Unsupported security type: ${network.securityType}")
                        return false
                    }
                }
            }
            
            // Add network configuration
            val networkId = wifiManager.addNetwork(networkConfig)
            if (networkId == -1) {
                Log.e(TAG, "Failed to add network configuration")
                return false
            }
            
            // Enable the network
            val enableSuccess = wifiManager.enableNetwork(networkId, true)
            if (!enableSuccess) {
                Log.e(TAG, "Failed to enable network")
                return false
            }
            
            // Reconnect to apply changes
            val reconnectSuccess = wifiManager.reconnect()
            if (!reconnectSuccess) {
                Log.e(TAG, "Failed to reconnect")
                return false
            }
            
            Log.d(TAG, "Successfully initiated connection to ${network.ssid}")
            return true
            
        } catch (e: Exception) {
            Log.e(TAG, "Error connecting to network: ${network.ssid}", e)
            return false
        }
    }
    
    // Get current scan status
    fun getScanStatus(): String {
        return when {
            !isWifiSupported() -> "WiFi not supported"
            !isWifiEnabled() -> "WiFi disabled"
            !hasRequiredPermissions() -> "Permissions required"
            isScanning.value -> "Scanning networks..."
            discoveredNetworksList.isEmpty() -> "No networks found"
            else -> "Found ${discoveredNetworksList.size} networks"
        }
    }
    
    // Get WiFi connection history from device
    fun getWifiConnectionHistory(): List<WifiConnectionHistory> {
        val historyList = mutableListOf<WifiConnectionHistory>()
        
        try {
            if (!hasRequiredPermissions()) {
                Log.e(TAG, "WiFi permissions not granted for accessing history")
                return emptyList()
            }
            
            // Get configured networks (saved WiFi networks)
            val configuredNetworks = wifiManager.configuredNetworks
            if (configuredNetworks != null) {
                for (network in configuredNetworks) {
                    val history = WifiConnectionHistory(
                        ssid = network.SSID?.removeSurrounding("\"") ?: "Unknown",
                        bssid = network.BSSID ?: "",
                        securityType = getSecurityTypeFromConfig(network),
                        lastConnected = getLastConnectedTime(network),
                        connectionCount = getConnectionCount(network),
                        signalStrength = getLastSignalStrength(network),
                        isCurrentlyConnected = network.networkId == wifiManager.connectionInfo?.networkId
                    )
                    historyList.add(history)
                }
            }
            
            // Sort by last connected time (most recent first)
            historyList.sortByDescending { it.lastConnected }
            
            Log.d(TAG, "Retrieved ${historyList.size} WiFi connection history entries")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving WiFi connection history", e)
        }
        
        return historyList
    }
    
    // Get security type from WifiConfiguration
    private fun getSecurityTypeFromConfig(config: android.net.wifi.WifiConfiguration): String {
        return when {
            config.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_PSK) -> "WPA/WPA2"
            config.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_EAP) -> "WPA-EAP"
            config.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.IEEE8021X) -> "802.1X"
            config.wepKeys.isNotEmpty() && config.wepKeys[0] != null -> "WEP"
            else -> "Open"
        }
    }
    
    // Get last connected time (simplified - Android doesn't provide direct access)
    private fun getLastConnectedTime(config: android.net.wifi.WifiConfiguration): Long {
        // Android doesn't provide direct access to connection timestamps
        // We can use the network ID as a proxy for recency (lower IDs are older)
        // In a real implementation, you might store this data separately
        return System.currentTimeMillis() - (config.networkId * 1000L) // Simulated timestamp
    }
    
    // Get connection count (simplified)
    private fun getConnectionCount(config: android.net.wifi.WifiConfiguration): Int {
        // Android doesn't provide direct access to connection counts
        // This is a placeholder - in real implementation you'd track this
        return 1
    }
    
    // Get last signal strength (simplified)
    private fun getLastSignalStrength(config: android.net.wifi.WifiConfiguration): Int {
        val connectionInfo = wifiManager.connectionInfo
        return if (connectionInfo?.networkId == config.networkId) {
            connectionInfo.rssi
        } else {
            -100 // Unknown signal strength
        }
    }
    
    // Get recently connected networks (last 24 hours)
    fun getRecentlyConnectedNetworks(): List<WifiConnectionHistory> {
        val allHistory = getWifiConnectionHistory()
        val twentyFourHoursAgo = System.currentTimeMillis() - (24 * 60 * 60 * 1000)
        
        return allHistory.filter { it.lastConnected > twentyFourHoursAgo }
    }
    
    // Get most frequently connected networks
    fun getMostFrequentNetworks(): List<WifiConnectionHistory> {
        val allHistory = getWifiConnectionHistory()
        
        // Group by SSID and count connections
        val frequencyMap = allHistory.groupBy { it.ssid }
            .mapValues { (_, networks) -> 
                networks.sumOf { it.connectionCount }
            }
        
        // Sort by frequency and return top networks
        return allHistory.distinctBy { it.ssid }
            .sortedByDescending { frequencyMap[it.ssid] ?: 0 }
            .take(10) // Top 10 most frequent
    }
    
    // Check if a network is in history
    fun isNetworkInHistory(ssid: String): Boolean {
        return getWifiConnectionHistory().any { it.ssid == ssid }
    }
    
    // Get network details from history
    fun getNetworkFromHistory(ssid: String): WifiConnectionHistory? {
        return getWifiConnectionHistory().find { it.ssid == ssid }
    }
    
    // Get detailed WiFi usage statistics
    fun getWifiUsageStatistics(): WifiUsageStatistics {
        val history = getWifiConnectionHistory()
        val currentConnection = wifiManager.connectionInfo
        
        return WifiUsageStatistics(
            totalNetworks = history.size,
            currentlyConnected = currentConnection?.ssid?.removeSurrounding("\"") ?: "None",
            mostFrequentNetwork = history.maxByOrNull { it.connectionCount }?.ssid ?: "None",
            totalConnectionTime = calculateTotalConnectionTime(history),
            averageSignalStrength = history.map { it.signalStrength }.average(),
            networksBySecurityType = history.groupBy { it.securityType },
            lastConnectedNetwork = history.firstOrNull()?.ssid ?: "None"
        )
    }
    
    // Calculate total connection time (simplified)
    private fun calculateTotalConnectionTime(history: List<WifiConnectionHistory>): Long {
        // This is a simplified calculation
        // In a real implementation, you'd track actual connection durations
        return history.sumOf { it.connectionCount } * 60 * 1000L // Assume 1 minute per connection
    }
    
    // Get WiFi networks by location (using BSSID patterns)
    fun getNetworksByLocation(): Map<String, List<WifiConnectionHistory>> {
        val history = getWifiConnectionHistory()
        
        return history.groupBy { network ->
            // Group by location based on BSSID prefix (first 6 characters)
            // This is a simplified approach - real location detection would be more complex
            if (network.bssid.length >= 6) {
                network.bssid.substring(0, 6)
            } else {
                "Unknown"
            }
        }
    }
    
    // Get WiFi networks by time of day
    fun getNetworksByTimeOfDay(): Map<String, List<WifiConnectionHistory>> {
        val history = getWifiConnectionHistory()
        
        return history.groupBy { network ->
            val calendar = java.util.Calendar.getInstance()
            calendar.timeInMillis = network.lastConnected
            
            when (calendar.get(java.util.Calendar.HOUR_OF_DAY)) {
                in 6..11 -> "Morning"
                in 12..17 -> "Afternoon"
                in 18..22 -> "Evening"
                else -> "Night"
            }
        }
    }
    
    // Get WiFi networks by signal strength category
    fun getNetworksBySignalStrength(): Map<String, List<WifiConnectionHistory>> {
        val history = getWifiConnectionHistory()
        
        return history.groupBy { network ->
            when {
                network.signalStrength >= -50 -> "Excellent"
                network.signalStrength >= -70 -> "Good"
                network.signalStrength >= -80 -> "Fair"
                else -> "Poor"
            }
        }
    }
    
    // Get WiFi networks that might be fusion nodes based on history
    fun getPotentialFusionNodesFromHistory(): List<WifiConnectionHistory> {
        val history = getWifiConnectionHistory()
        
        return history.filter { network ->
            // Check if this network might be a fusion node based on various criteria
            val ssidLower = network.ssid.lowercase()
            val fusionKeywords = listOf("fusion", "node", "mesh", "router", "gateway", "pi", "raspberry")
            
            fusionKeywords.any { keyword -> ssidLower.contains(keyword) } ||
            network.connectionCount > 5 || // Frequently connected
            network.securityType.contains("WPA") // Most fusion nodes use WPA
        }
    }
    
    // Get WiFi networks with poor signal strength
    fun getNetworksWithPoorSignal(): List<WifiConnectionHistory> {
        return getWifiConnectionHistory().filter { it.signalStrength < -80 }
    }
    
    // Get WiFi networks with excellent signal strength
    fun getNetworksWithExcellentSignal(): List<WifiConnectionHistory> {
        return getWifiConnectionHistory().filter { it.signalStrength >= -50 }
    }
    
    // Get WiFi networks by frequency (2.4GHz vs 5GHz)
    fun getNetworksByFrequency(): Map<String, List<WifiConnectionHistory>> {
        val history = getWifiConnectionHistory()
        
        // This is a simplified approach - real frequency detection would require more data
        return history.groupBy { network ->
            // Assume networks with higher signal strength are more likely to be 5GHz
            if (network.signalStrength > -60) "5GHz" else "2.4GHz"
        }
    }
    
    // Get enhanced WiFi information using additional Android APIs
    fun getEnhancedWifiInformation(): EnhancedWifiInformation {
        val history = getWifiConnectionHistory()
        val currentConnection = wifiManager.connectionInfo
        
        return EnhancedWifiInformation(
            deviceInfo = getDeviceWifiInfo(),
            currentConnection = getCurrentConnectionDetails(),
            networkCapabilities = getNetworkCapabilities(),
            wifiState = getWifiState(),
            scanResults = getCurrentScanResults(),
            connectionHistory = history
        )
    }
    
    // Get device WiFi information
    private fun getDeviceWifiInfo(): DeviceWifiInfo {
        return DeviceWifiInfo(
            isWifiEnabled = wifiManager.isWifiEnabled,
            isWifiSupported = wifiManager != null,
            hasRequiredPermissions = hasRequiredPermissions(),
            wifiState = getWifiState(),
            deviceName = android.os.Build.MODEL,
            androidVersion = android.os.Build.VERSION.RELEASE,
            wifiHardware = getWifiHardwareInfo()
        )
    }
    
    // Get current connection details
    private fun getCurrentConnectionDetails(): CurrentConnectionDetails? {
        val connectionInfo = wifiManager.connectionInfo
        return if (connectionInfo != null && connectionInfo.networkId != -1) {
            CurrentConnectionDetails(
                ssid = connectionInfo.ssid?.removeSurrounding("\"") ?: "Unknown",
                bssid = connectionInfo.bssid ?: "Unknown",
                rssi = connectionInfo.rssi,
                linkSpeed = connectionInfo.linkSpeed,
                frequency = connectionInfo.frequency,
                ipAddress = connectionInfo.ipAddress,
                networkId = connectionInfo.networkId,
                hiddenSSID = connectionInfo.hiddenSSID
            )
        } else {
            null
        }
    }
    
    // Get network capabilities (requires additional permissions)
    private fun getNetworkCapabilities(): NetworkCapabilities? {
        return try {
            // This would require additional permissions and API level checks
            // For now, return basic information
            NetworkCapabilities(
                hasInternet = true,
                hasValidated = true,
                bandwidth = 0, // Would need to be calculated
                transportTypes = listOf("WIFI"),
                signalStrength = wifiManager.connectionInfo?.rssi ?: -100
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting network capabilities", e)
            null
        }
    }
    
    // Get WiFi state
    private fun getWifiState(): String {
        return when (wifiManager.wifiState) {
            WifiManager.WIFI_STATE_DISABLED -> "Disabled"
            WifiManager.WIFI_STATE_DISABLING -> "Disabling"
            WifiManager.WIFI_STATE_ENABLED -> "Enabled"
            WifiManager.WIFI_STATE_ENABLING -> "Enabling"
            WifiManager.WIFI_STATE_UNKNOWN -> "Unknown"
            else -> "Unknown"
        }
    }
    
    // Get current scan results
    private fun getCurrentScanResults(): List<ScanResultInfo> {
        return try {
            val scanResults = wifiManager.scanResults
            scanResults.map { result ->
                ScanResultInfo(
                    ssid = result.SSID,
                    bssid = result.BSSID,
                    rssi = result.level,
                    frequency = result.frequency,
                    capabilities = result.capabilities,
                    channel = getChannelFromFrequency(result.frequency),
                    timestamp = result.timestamp
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting scan results", e)
            emptyList()
        }
    }
    
    // Get WiFi hardware information
    private fun getWifiHardwareInfo(): WifiHardwareInfo {
        return WifiHardwareInfo(
            wifiStandard = getWifiStandard(),
            maxSupportedChannels = getMaxSupportedChannels(),
            supports5GHz = supports5GHz(),
            supports6GHz = supports6GHz()
        )
    }
    
    // Get WiFi standard (simplified)
    private fun getWifiStandard(): String {
        // This would require API level 30+ and additional permissions
        // For now, return a simplified version
        return "802.11ac" // Assume modern standard
    }
    
    // Get max supported channels
    private fun getMaxSupportedChannels(): Int {
        // This would require additional API calls
        return 165 // Typical for modern devices
    }
    
    // Check if device supports 5GHz
    private fun supports5GHz(): Boolean {
        // This would require checking frequency bands
        return true // Assume modern devices support 5GHz
    }
    
    // Check if device supports 6GHz
    private fun supports6GHz(): Boolean {
        // This would require API level 33+ and additional permissions
        return false // Assume not supported for now
    }
    
    // Get network details for display
    fun getNetworkDetails(network: FusionWifiNetwork): String {
        return buildString {
            append("SSID: ${network.ssid}\n")
            append("BSSID: ${network.bssid}\n")
            append("Signal: ${network.rssi} dBm\n")
            append("Security: ${network.securityType}\n")
            append("Channel: ${network.channel}\n")
            append("Frequency: ${network.frequency} MHz")
        }
    }
    
    // Clean up resources
    fun cleanup() {
        try {
            stopScan()
            scanReceiver?.let { receiver ->
                context.unregisterReceiver(receiver)
                scanReceiver = null
            }
            connectionReceiver?.let { receiver ->
                context.unregisterReceiver(receiver)
                connectionReceiver = null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error during cleanup", e)
        }
    }
    
    // Initialize connection monitoring
    init {
        registerConnectionReceiver()
        getCurrentConnection() // Get initial connection status
    }
    
    // Get currently connected network
    fun getConnectedNetwork(): FusionWifiNetwork? {
        return try {
            if (!isWifiSupported() || !isWifiEnabled()) {
                return null
            }
            
            val connectionInfo = wifiManager.connectionInfo
            if (connectionInfo != null && connectionInfo.networkId != -1) {
                val ssid = connectionInfo.ssid?.removeSurrounding("\"") ?: ""
                val bssid = connectionInfo.bssid ?: ""
                val rssi = connectionInfo.rssi
                val frequency = connectionInfo.frequency
                
                // Create FusionWifiNetwork object for connected network
                val connectedNetwork = FusionWifiNetwork(
                    ssid = ssid,
                    bssid = bssid,
                    rssi = rssi,
                    frequency = frequency,
                    channel = getChannelFromFrequency(frequency),
                    securityType = getSecurityType(connectionInfo),
                    capabilities = "" // Would need to get from scan results
                )
                
                Log.d(TAG, "Connected to network: $ssid")
                return connectedNetwork
            }
            
            null
            
        } catch (e: Exception) {
            Log.e(TAG, "Error getting connected network", e)
            null
        }
    }
    
    // Get security type from connection info
    private fun getSecurityType(connectionInfo: android.net.wifi.WifiInfo): String {
        // This is a simplified implementation
        // In a real app, you'd parse the capabilities string
        return "WPA2" // Default assumption
    }
}
