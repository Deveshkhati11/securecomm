package com.example.securecomm.ui.screens

import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.provider.Settings
import android.bluetooth.BluetoothAdapter
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.text.replaceFirstChar
import androidx.compose.ui.text.style.TextAlign
import android.util.Log
import android.content.ClipboardManager
import android.content.ClipData
import android.widget.Toast
import androidx.compose.material3.OutlinedTextFieldDefaults
import com.example.mine.viewmodel.SecureChatViewModel
import com.example.mine.network.TcpConnectionStatus
import androidx.compose.material3.CircularProgressIndicator

@Composable
fun ModernMainScreen(viewModel: SecureChatViewModel) {
    val context = LocalContext.current
    
    // Debug: Log ViewModel initialization
    LaunchedEffect(Unit) {
        Log.d("MainScreen", "ViewModel initialized: $viewModel")
    }
    
    var currentScreen by remember { mutableStateOf("start") }
    var connectionType by remember { mutableStateOf<String?>(null) }

    var connectionState by remember { mutableStateOf("disconnected") }
    var isCheckingConnection by remember { mutableStateOf(false) }
    var connectedDeviceInfo by remember { mutableStateOf<DeviceInfo?>(null) }
    
    // Get real fusion node information from ViewModel
    val connectedFusionNode by viewModel.connectedFusionNode.collectAsState()
    val publicKey by viewModel.publicKey.collectAsState()
    
    // Debug: Log fusion node changes
    LaunchedEffect(connectedFusionNode) {
        Log.d("MainScreen", "Fusion node changed: $connectedFusionNode")
    }
    
    // Debug: Log public key changes
    LaunchedEffect(publicKey) {
        Log.d("MainScreen", "Public key changed: ${publicKey != null}")
    }

    // Ensure public key exists when reaching manual key input screen
    LaunchedEffect(currentScreen) {
        if (currentScreen == "manual-key-input") {
            try {
                Log.d("MainScreen", "Manual key input screen reached, ensuring public key exists...")
                viewModel.ensurePublicKeyExists()
            } catch (e: Exception) {
                Log.e("MainScreen", "Error ensuring public key exists", e)
                // Continue without crashing
            }
        }
    }

    // Handle system back press to navigate to previous screen
    BackHandler(enabled = currentScreen != "start") {
        currentScreen = when (currentScreen) {
            "connection-type" -> "start"
            "connection-guide" -> "connection-type"
            "connection-status" -> "connection-guide"
            "node-listening" -> "connection-status"
            "manual-key-input" -> "node-listening"
            "key-generation" -> "manual-key-input"
            "chat" -> "start"
            else -> "start"
        }
    }

    // Check connection status when returning to app
    LaunchedEffect(Unit) {
        // Initial connection check
        checkConnectionStatus(
            context = context,
            connectionType = connectionType,
            onUpdateCheckingState = { isCheckingConnection = it },
            onUpdateConnectionState = { connectionState = it },
            onUpdateConnectedDevice = { connectedDeviceInfo = it }
        )
    }

    when (currentScreen) {
        "start" -> StartScreen(
            onDiscoverDevices = { currentScreen = "connection-type" }
        )
        "connection-type" -> ConnectionTypeScreen(
            onBack = { currentScreen = "start" },
            onSelectType = { type ->
                connectionType = type
                currentScreen = "connection-guide"
            }
        )
        "connection-guide" -> ConnectionGuideScreen(
            connectionType = connectionType ?: "bluetooth",
            onBack = { currentScreen = "connection-type" },
            onOpenSettings = { type ->
                openSettings(context, type)
            },
            onCheckConnection = {
                checkConnectionStatus(
                    context = context,
                    connectionType = connectionType,
                    onUpdateCheckingState = { isCheckingConnection = it },
                    onUpdateConnectionState = { connectionState = it },
                    onUpdateConnectedDevice = { connectedDeviceInfo = it }
                )
                currentScreen = "connection-status"
            }
        )
        "connection-status" -> ConnectionStatusScreen(
            connectionType = connectionType ?: "bluetooth",
            connectionState = connectionState,
            connectedDeviceInfo = connectedDeviceInfo,
            isCheckingConnection = isCheckingConnection,
            onBack = { currentScreen = "connection-guide" },
            onRetry = {
                checkConnectionStatus(
                    context = context,
                    connectionType = connectionType,
                    onUpdateCheckingState = { isCheckingConnection = it },
                    onUpdateConnectionState = { connectionState = it },
                    onUpdateConnectedDevice = { connectedDeviceInfo = it }
                )
            },
            onContinue = { currentScreen = "node-listening" }
        )
        "node-listening" -> NodeListeningScreen(
            selectedDevice = connectedDeviceInfo,
            viewModel = viewModel,
            onContinue = { currentScreen = "manual-key-input" }
        )
        "manual-key-input" -> ManualKeyInputScreen(
            onContinue = { currentScreen = "key-generation" },
            viewModel = viewModel
        )
        "key-generation" -> KeyGenerationScreen(
            onContinue = { currentScreen = "chat" },
            viewModel = viewModel
        )
        "chat" -> ChatScreen(
            selectedDevice = connectedDeviceInfo,
            viewModel = viewModel,
            onReset = { currentScreen = "start" }
        )
    }
}

// Extracted function to handle connection checking
fun checkConnectionStatus(
    context: Context,
    connectionType: String?,
    onUpdateCheckingState: (Boolean) -> Unit,
    onUpdateConnectionState: (String) -> Unit,
    onUpdateConnectedDevice: (DeviceInfo?) -> Unit
) {
    onUpdateCheckingState(true)
    // Check connection based on selected type
    CoroutineScope(Dispatchers.Main).launch {
        delay(1000) // Simulate check time

        // Check actual device connection status using await() for suspend functions
        val isConnected = when (connectionType) {
            "bluetooth" -> checkBluetoothConnection(context)
            "wifi" -> checkWifiConnection(context)
            else -> false
        }

        if (isConnected) {
            onUpdateConnectionState("connected")
            // Get connected device info in a safe way
            val deviceInfo = when (connectionType) {
                "bluetooth" -> getBluetoothDeviceInfo(context)
                "wifi" -> getWifiDeviceInfo(context)
                else -> null
            }
            onUpdateConnectedDevice(deviceInfo)
        } else {
            onUpdateConnectionState("disconnected")
            onUpdateConnectedDevice(null)
        }

        onUpdateCheckingState(false)
    }
}

// Real connection checking functions
suspend fun checkBluetoothConnection(context: Context): Boolean {
    return try {
        // Check if Bluetooth permissions are granted
        val permissionManager = com.example.mine.utils.PermissionManager(context)
        if (!permissionManager.hasBluetoothPermissions()) {
            return false // Permission not granted
        }
        
        val bluetoothAdapter = android.bluetooth.BluetoothAdapter.getDefaultAdapter()
        if (bluetoothAdapter != null && bluetoothAdapter.isEnabled) {
            // Access bonded devices in a safe way to avoid composition issues
            val bondedDevices = bluetoothAdapter.bondedDevices
            bondedDevices.isNotEmpty()
        } else {
            false
        }
    } catch (e: SecurityException) {
        // Handle SecurityException when permission is denied
        false
    } catch (e: Exception) {
        false
    }
}

suspend fun checkWifiConnection(context: Context): Boolean {
    return try {
        // Check if WiFi permissions are granted
        val accessWifiState = android.Manifest.permission.ACCESS_WIFI_STATE
        val accessNetworkState = android.Manifest.permission.ACCESS_NETWORK_STATE
        
        if (androidx.core.content.ContextCompat.checkSelfPermission(context, accessWifiState) != android.content.pm.PackageManager.PERMISSION_GRANTED ||
            androidx.core.content.ContextCompat.checkSelfPermission(context, accessNetworkState) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return false // Permission not granted
        }
        
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val connectionInfo = wifiManager.connectionInfo
        connectionInfo != null && connectionInfo.networkId != -1
    } catch (e: SecurityException) {
        // Handle SecurityException when permission is denied
        false
    } catch (e: Exception) {
        false
    }
}

// Function to get fusion node ID from WiFi connection
fun getFusionNodeIdFromWifi(context: Context): String? {
    return try {
        // Check if WiFi permissions are granted
        val accessWifiState = android.Manifest.permission.ACCESS_WIFI_STATE
        val accessNetworkState = android.Manifest.permission.ACCESS_NETWORK_STATE
        
        if (androidx.core.content.ContextCompat.checkSelfPermission(context, accessWifiState) != android.content.pm.PackageManager.PERMISSION_GRANTED ||
            androidx.core.content.ContextCompat.checkSelfPermission(context, accessNetworkState) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return null // Permission not granted
        }
        
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val connectionInfo = wifiManager.connectionInfo
        if (connectionInfo != null && connectionInfo.networkId != -1) {
            // Simulate getting fusion node ID from connected node
            // In real implementation, this would:
            // 1. Connect to the WiFi network
            // 2. Send a request to the connected node
            // 3. Parse JSON response like: {"fusion_node_id": "FN_ABC123", "status": "connected"}
            // 4. Extract and return the fusion_node_id
            
            // For demo purposes, generate a realistic-looking fusion node ID
            val networkName = connectionInfo.ssid?.removeSurrounding("\"") ?: "Unknown"
            "FN_${networkName.take(3).uppercase()}_${(1000..9999).random()}"
        } else null
    } catch (e: SecurityException) {
        // Handle SecurityException when permission is denied
        null
    } catch (e: Exception) {
        null
    }
}

// Safe function to get Bluetooth device info
fun getBluetoothDeviceInfo(context: Context): DeviceInfo? {
    return try {
        // Check if Bluetooth permissions are granted
        val permissionManager = com.example.mine.utils.PermissionManager(context)
        if (!permissionManager.hasBluetoothPermissions()) {
            return null // Permission not granted
        }
        
        val bluetoothAdapter = android.bluetooth.BluetoothAdapter.getDefaultAdapter()
        if (bluetoothAdapter != null && bluetoothAdapter.isEnabled) {
            val bondedDevices = bluetoothAdapter.bondedDevices
            if (bondedDevices.isNotEmpty()) {
                val device = bondedDevices.first()
                DeviceInfo(
                    id = device.address,
                    name = device.name ?: "Unknown Bluetooth Device",
                    signal = 85,
                    type = "bluetooth",
                    status = "Connected"
                )
            } else null
        } else null
    } catch (e: SecurityException) {
        // Handle SecurityException when permission is denied
        null
    } catch (e: Exception) {
        null
    }
}

// Safe function to get WiFi device info
fun getWifiDeviceInfo(context: Context): DeviceInfo? {
    return try {
        // Check if WiFi permissions are granted
        val accessWifiState = android.Manifest.permission.ACCESS_WIFI_STATE
        val accessNetworkState = android.Manifest.permission.ACCESS_NETWORK_STATE
        
        if (androidx.core.content.ContextCompat.checkSelfPermission(context, accessWifiState) != android.content.pm.PackageManager.PERMISSION_GRANTED ||
            androidx.core.content.ContextCompat.checkSelfPermission(context, accessNetworkState) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return null // Permission not granted
        }
        
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val connectionInfo = wifiManager.connectionInfo
        if (connectionInfo != null && connectionInfo.networkId != -1) {
            DeviceInfo(
                id = connectionInfo.bssid ?: "unknown",
                name = connectionInfo.ssid?.removeSurrounding("\"") ?: "Unknown WiFi Network",
                signal = WifiManager.calculateSignalLevel(connectionInfo.rssi, 5) * 20, // Convert to percentage
                type = "wifi",
                status = "Connected"
            )
        } else null
    } catch (e: SecurityException) {
        // Handle SecurityException when permission is denied
        null
    } catch (e: Exception) {
        null
    }
}

// Function to open settings
fun openSettings(context: Context, connectionType: String) {
    val intent = when (connectionType) {
        "bluetooth" -> Intent(Settings.ACTION_BLUETOOTH_SETTINGS)
        "wifi" -> Intent(Settings.ACTION_WIFI_SETTINGS)
        else -> Intent(Settings.ACTION_SETTINGS)
    }
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(intent)
}

// Data classes
data class DeviceInfo(
    val id: String,
    val name: String,
    val signal: Int,
    val type: String,
    val status: String = "available"
)

// Start Screen
@Composable
fun StartScreen(onDiscoverDevices: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF1E3A8A), // indigo-900
                        Color(0xFF7C3AED), // purple-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // App Icon
            Box(
                modifier = Modifier
                    .size(96.dp)
                    .clip(RoundedCornerShape(48.dp))
                    .background(
                        Brush.horizontalGradient(
                            colors = listOf(
                                Color(0xFF22D3EE), // cyan-400
                                Color(0xFFA855F7)  // purple-500
                            )
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Router,
                    contentDescription = "Router Icon",
                    tint = Color.White,
                    modifier = Modifier.size(48.dp)
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // App Title
            Text(
                text = "Fusion Node App",
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Subtitle
            Text(
                text = "Secure device-to-device communication",
                fontSize = 16.sp,
                color = Color(0xFFC4B5FD) // purple-200
            )

            Spacer(modifier = Modifier.height(64.dp))

            // Discover Button
            Button(
                onClick = onDiscoverDevices,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(64.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF06B6D4), // cyan-500
                                    Color(0xFF9333EA)  // purple-600
                                )
                            ),
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Smartphone,
                            contentDescription = "Smartphone Icon",
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "Discover Devices",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

// Connection Type Selection Screen
@Composable
fun ConnectionTypeScreen(
    onBack: () -> Unit,
    onSelectType: (String) -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF1E40AF), // blue-900
                        Color(0xFF3730A3), // indigo-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Select Connection Type",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Choose how you want to connect to devices",
                    fontSize = 16.sp,
                    color = Color(0xFFBFDBFE) // blue-200
                )
            }

            Spacer(modifier = Modifier.height(48.dp))

            // Bluetooth Option
            Button(
                onClick = { onSelectType("bluetooth") },
                modifier = Modifier
                    .fillMaxWidth(0.9f)
                    .align(Alignment.CenterHorizontally)
                    .heightIn(min = 120.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF2563EB), // blue-600
                                    Color(0xFF0891B2)  // cyan-600
                                )
                            ),
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 24.dp, vertical = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .clip(RoundedCornerShape(24.dp))
                                .background(Color.White.copy(alpha = 0.2f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Wifi,
                                contentDescription = "Bluetooth Icon",
                                tint = Color.White,
                                modifier = Modifier.size(24.dp)
                            )
                        }

                        Column {
                            Text(
                                text = "Bluetooth",
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )

                            Text(
                                text = "Connect via Bluetooth Low Energy",
                                fontSize = 14.sp,
                                color = Color(0xFFDBEAFE) // blue-100
                            )

                            Text(
                                text = "Range: ~100m • Power efficient",
                                fontSize = 12.sp,
                                color = Color(0xFFBFDBFE) // blue-200
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Wi-Fi Option
            Button(
                onClick = { onSelectType("wifi") },
                modifier = Modifier
                    .fillMaxWidth(0.9f)
                    .align(Alignment.CenterHorizontally)
                    .heightIn(min = 120.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF9333EA), // purple-600
                                    Color(0xFFDB2777)  // pink-600
                                )
                            ),
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 24.dp, vertical = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .clip(RoundedCornerShape(24.dp))
                                .background(Color.White.copy(alpha = 0.2f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Router,
                                contentDescription = "Wi-Fi Icon",
                                tint = Color.White,
                                modifier = Modifier.size(24.dp)
                            )
                        }

                        Column {
                            Text(
                                text = "Wi-Fi",
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )

                            Text(
                                text = "Connect via Wi-Fi networks",
                                fontSize = 14.sp,
                                color = Color(0xFFFCE7F3) // pink-100
                            )

                            Text(
                                text = "Range: ~300m • High bandwidth",
                                fontSize = 12.sp,
                                color = Color(0xFFFBCFE8) // pink-200
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Back Button
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = Color(0xFF4B5563) // gray-600
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Back",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

// Connection Guide Screen
@Composable
fun ConnectionGuideScreen(
    connectionType: String,
    onBack: () -> Unit,
    onOpenSettings: (String) -> Unit,
    onCheckConnection: () -> Unit
) {
    val title = if (connectionType == "bluetooth") "Bluetooth Connection Guide" else "Wi-Fi Connection Guide"
    val icon = if (connectionType == "bluetooth") Icons.Default.Wifi else Icons.Default.Router
    val instructions = if (connectionType == "bluetooth") {
        listOf(
            "1. Go to your phone's Settings",
            "2. Navigate to Bluetooth settings",
            "3. Turn on Bluetooth if not already on",
            "4. Scan for available devices",
            "5. Select and pair with your desired device",
            "6. Return to this app when connected"
        )
    } else {
        listOf(
            "1. Go to your phone's Settings",
            "2. Navigate to Wi-Fi settings",
            "3. Turn on Wi-Fi if not already on",
            "4. Select your desired network",
            "5. Enter password if required",
            "6. Return to this app when connected"
        )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF111827), // gray-900
                        Color(0xFF1E40AF), // blue-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(RoundedCornerShape(40.dp))
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF22D3EE), // cyan-400
                                    Color(0xFFA855F7)  // purple-500
                                )
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = "Connection Icon",
                        tint = Color.White,
                        modifier = Modifier.size(40.dp)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = title,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Follow these steps to connect manually",
                    fontSize = 16.sp,
                    color = Color(0xFFBFDBFE) // blue-200
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Instructions Card
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp)
                ) {
                    Text(
                        text = "Connection Steps:",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF34D399) // green-400
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    instructions.forEach { instruction ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = instruction,
                                fontSize = 16.sp,
                                color = Color.White,
                                modifier = Modifier.weight(1f)
                            )
                        }

                        if (instruction != instructions.last()) {
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Important Note
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF7C2D12).copy(alpha = 0.3f) // orange-900/30
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = Color(0xFFFB923C) // orange-400
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = "Info Icon",
                        tint = Color(0xFFFB923C), // orange-400
                        modifier = Modifier.size(24.dp)
                    )

                    Text(
                        text = "Important: Make sure you're connected to a device before returning to this app. The app will verify your connection when you return.",
                        fontSize = 14.sp,
                        color = Color(0xFFFED7AA) // orange-200
                    )
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Open Settings Button
            Button(
                onClick = { onOpenSettings(connectionType) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFFF59E0B), // amber-500
                                    Color(0xFFEF4444)  // red-500
                                )
                            ),
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings Icon",
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            text = "Open ${connectionType.replaceFirstChar { it.uppercase() }} Settings",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Check Connection Button
            Button(
                onClick = onCheckConnection,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF10B981), // green-500
                                    Color(0xFF3B82F6)  // blue-600
                                )
                            ),
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Check,
                            contentDescription = "Check Icon",
                            tint = Color.White,
                            modifier = Modifier.size(24.dp)
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            text = "Check Connection Status",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Back Button
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = Color(0xFF4B5563) // gray-600
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Back to Connection Types",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

// Device List Screen
@Composable
fun DeviceListScreen(
    connectionType: String,
    onBack: () -> Unit,
    onDeviceSelect: (DeviceInfo) -> Unit
) {
    val devices = remember {
        if (connectionType == "bluetooth") {
            listOf(
                DeviceInfo("BT_001", "AADI Fusion BT", 88, "bluetooth", "Available"),
                DeviceInfo("BT_002", "Relay Node BT", 75, "bluetooth", "Paired"),
                DeviceInfo("BT_003", "Smart Device BT", 92, "bluetooth", "Available")
            )
        } else {
            listOf(
                DeviceInfo("WIFI_001", "FusionNet_5G", 92, "wifi", "Secured"),
                DeviceInfo("WIFI_002", "AADI_Network", 67, "wifi", "Secured"),
                DeviceInfo("WIFI_003", "OpenNetwork", 45, "wifi", "Open")
            )
        }
    }

    val title = if (connectionType == "bluetooth") "Bluetooth Devices" else "Wi-Fi Networks"
    val icon = if (connectionType == "bluetooth") Icons.Default.Wifi else Icons.Default.Router

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF111827), // gray-900
                        Color(0xFF1E40AF), // blue-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(RoundedCornerShape(32.dp))
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF22D3EE), // cyan-400
                                    Color(0xFFA855F7)  // purple-500
                                )
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = "Connection Icon",
                        tint = Color.White,
                        modifier = Modifier.size(32.dp)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = title,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Scanning for available $connectionType devices...",
                    fontSize = 16.sp,
                    color = Color(0xFFBFDBFE) // blue-200
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Device List
            devices.forEach { device ->
                DeviceItem(
                    device = device,
                    connectionType = connectionType,
                    onClick = { onDeviceSelect(device) }
                )

                Spacer(modifier = Modifier.height(16.dp))
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Back Button
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = Color(0xFF4B5563) // gray-600
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Back to Connection Types",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

@Composable
fun DeviceItem(
    device: DeviceInfo,
    connectionType: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
        ),
        border = BorderStroke(
            width = 1.dp,
            color = Color(0xFF4B5563) // gray-600
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                ) {
                    Icon(
                        imageVector = if (connectionType == "bluetooth") Icons.Default.Wifi else Icons.Default.Router,
                        contentDescription = "Device Icon",
                        tint = if (connectionType == "bluetooth") Color(0xFF60A5FA) else Color(0xFFC084FC),
                        modifier = Modifier.size(24.dp)
                    )

                    // Status indicator
                    if (device.status == "Paired" || device.status == "Secured") {
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .background(
                                    color = if (device.status == "Paired") Color(0xFF34D399) else Color(0xFFFBBF24),
                                    shape = CircleShape
                                )
                        )
                    }
                }

                Column {
                    Text(
                        text = device.name,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color.White
                    )

                    Text(
                        text = device.status,
                        fontSize = 14.sp,
                        color = Color(0xFF9CA3AF) // gray-400
                    )
                }
            }

            Column(
                horizontalAlignment = Alignment.End
            ) {
                Text(
                    text = "${device.signal}%",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF34D399) // green-400
                )

                Text(
                    text = "Signal",
                    fontSize = 12.sp,
                    color = Color(0xFF9CA3AF) // gray-400
                )
            }
        }
    }
}

// Phone Settings Screen
@Composable
fun PhoneSettingsScreen(
    selectedDevice: DeviceInfo?,
    connectionType: String?,
    onBack: () -> Unit,
    onConnect: () -> Unit,
    isConnecting: Boolean
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF064E3B), // green-900
                        Color(0xFF134E4A), // teal-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Settings Icon",
                    tint = Color(0xFF34D399), // green-400
                    modifier = Modifier.size(64.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Phone Settings",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Configure connection settings",
                    fontSize = 16.sp,
                    color = Color(0xFFBBF7D0) // green-200
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Selected Device Info
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = "Selected Device",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF34D399) // green-400
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(20.dp))
                                .background(Color(0xFF10B981).copy(alpha = 0.2f)), // green-500/20
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (connectionType == "bluetooth") Icons.Default.Wifi else Icons.Default.Router,
                                contentDescription = "Device Icon",
                                tint = if (connectionType == "bluetooth") Color(0xFF60A5FA) else Color(0xFFC084FC),
                                modifier = Modifier.size(20.dp)
                            )
                        }

                        Column {
                            Text(
                                text = selectedDevice?.name ?: "Unknown Device",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )

                            Text(
                                text = "${connectionType?.replaceFirstChar { it.uppercase() } ?: "Unknown"} • ${selectedDevice?.signal ?: 0}% signal",
                                fontSize = 14.sp,
                                color = Color(0xFF9CA3AF) // gray-400
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Connection Settings
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = "Connection Settings",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF34D399) // green-400
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Auto-connect toggle
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Auto-connect",
                            fontSize = 16.sp,
                            color = Color.White
                        )

                        Switch(
                            checked = true,
                            onCheckedChange = { },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = Color(0xFF10B981) // green-500
                            )
                        )
                    }

                    // Encryption toggle
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Encryption",
                            fontSize = 16.sp,
                            color = Color.White
                        )

                        Switch(
                            checked = true,
                            onCheckedChange = { },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = Color(0xFF10B981) // green-500
                            )
                        )
                    }

                    // Background sync toggle
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Background sync",
                            fontSize = 16.sp,
                            color = Color.White
                        )

                        Switch(
                            checked = false,
                            onCheckedChange = { },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = Color(0xFF10B981), // green-500
                                uncheckedTrackColor = Color(0xFF4B5563) // gray-600
                            )
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Connect Button
            Button(
                onClick = onConnect,
                enabled = !isConnecting,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF10B981), // green-500
                                    Color(0xFF0D9488)  // teal-600
                                )
                            ),
                            RoundedCornerShape(12.dp)
                        )
                ) {
                    if (isConnecting) {
                        Row(
                            modifier = Modifier.fillMaxSize(),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            Text(
                                text = "Connecting...",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )
                        }
                    } else {
                        Text(
                            text = "Connect to Device",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White,
                            modifier = Modifier.align(Alignment.Center)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Back Button
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = Color(0xFF4B5563) // gray-600
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Back to Device List",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}



// Node Listening Screen
@Composable
fun NodeListeningScreen(
    selectedDevice: DeviceInfo?,
    viewModel: SecureChatViewModel,
    onContinue: () -> Unit
) {
    val context = LocalContext.current
    var isListening by remember { mutableStateOf(true) }
    var receivedNodeId by remember { mutableStateOf<String?>(null) }
    var connectionStatus by remember { mutableStateOf("Connecting to fusion node...") }
    
    // Start listening for fusion node ID when screen is displayed
    LaunchedEffect(Unit) {
        viewModel.startListeningForNodeId()
    }
    
    // Observe the connected fusion node ID from ViewModel
    val connectedNodeId by viewModel.connectedFusionNode.collectAsState()
    val tcpConnectionStatus by viewModel.tcpConnectionStatus.collectAsState()
    
    LaunchedEffect(connectedNodeId) {
        if (connectedNodeId != null) {
            receivedNodeId = connectedNodeId
            connectionStatus = "Fusion node ID received!"
        }
    }
    
    // Update connection status based on TCP connection
    LaunchedEffect(tcpConnectionStatus) {
        val currentStatus = tcpConnectionStatus
        connectionStatus = when (currentStatus) {
            is TcpConnectionStatus.Connecting -> "Connecting to fusion node..."
            is TcpConnectionStatus.Connected -> "Connected to fusion node, listening for ID..."
            is TcpConnectionStatus.ConnectedWithNodeId -> {
                receivedNodeId = currentStatus.nodeId
                "Fusion node ID received: ${currentStatus.nodeId}"
            }
            is TcpConnectionStatus.Failed -> "Connection failed: ${currentStatus.error}"
            else -> "Disconnected from fusion node"
        }
    }
    
    // Stop listening when leaving the screen
    DisposableEffect(Unit) {
        onDispose {
            viewModel.stopListeningForNodeId()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF92400E), // yellow-900
                        Color(0xFFEA580C), // orange-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Status Icon
            Box(
                modifier = Modifier
                    .size(80.dp)
                    .clip(RoundedCornerShape(40.dp))
                    .background(
                        Brush.horizontalGradient(
                            colors = if (receivedNodeId != null) {
                                listOf(
                                    Color(0xFF10B981), // green-500
                                Color(0xFF3B82F6)  // blue-500
                            )
                            } else {
                                listOf(
                                    Color(0xFFFBBF24), // yellow-400
                                    Color(0xFFFB923C)  // orange-500
                                )
                            }
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                if (receivedNodeId != null) {
                Icon(
                    imageVector = Icons.Default.Check,
                        contentDescription = "Success",
                    tint = Color.White,
                    modifier = Modifier.size(40.dp)
                )
                } else {
                    CircularProgressIndicator(
                        modifier = Modifier.size(40.dp),
                        color = Color.White,
                        strokeWidth = 4.dp
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Title
            Text(
                text = if (receivedNodeId != null) "Fusion Node Connected!" else "Listening for Fusion Node",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Status
            Text(
                text = connectionStatus,
                fontSize = 16.sp,
                color = if (receivedNodeId != null) Color(0xFFBBF7D0) else Color(0xFFFED7AA), // green-200 or yellow-200
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(32.dp))

            // Node ID Display
            if (receivedNodeId != null) {
            Card(
                colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF064E3B).copy(alpha = 0.8f) // green-900/80
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                        modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                        Icon(
                            imageVector = Icons.Default.Router,
                            contentDescription = "Fusion Node",
                            tint = Color(0xFF34D399), // green-400
                            modifier = Modifier.size(32.dp)
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                    Text(
                            text = "Fusion Node ID",
                            fontSize = 16.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF34D399) // green-400
                    )

                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = receivedNodeId!!,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            textAlign = TextAlign.Center
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        // Copy Button
                        Button(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("Fusion Node ID", receivedNodeId)
                                clipboard.setPrimaryClip(clip)
                                Toast.makeText(context, "Node ID copied to clipboard", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(40.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(
                                        Brush.horizontalGradient(
                                            colors = listOf(
                                                Color(0xFF34D399), // green-500
                                                Color(0xFF3B82F6)  // blue-500
                                            )
                                        ),
                                        RoundedCornerShape(12.dp)
                                    )
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                                        imageVector = Icons.Default.ContentCopy,
                                        contentDescription = "Copy Icon",
                                        tint = Color.White,
                            modifier = Modifier.size(16.dp)
                        )

                                    Spacer(modifier = Modifier.width(8.dp))

                        Text(
                                        text = "Copy Node ID",
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Color.White
                                    )
                                }
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(24.dp))

                // Test ESP32 Connection Button (for debugging)
                Button(
                    onClick = { 
                        viewModel.testEsp32Connection()
                        viewModel.debugCurrentState()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFFF59E0B), // amber-500
                                        Color(0xFFEF4444)  // red-500
                                    )
                                ),
                                RoundedCornerShape(12.dp)
                            )
                    ) {
                        Row(
                            modifier = Modifier.fillMaxSize(),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Settings,
                                contentDescription = "Test Icon",
                                tint = Color.White,
                                modifier = Modifier.size(20.dp)
                            )
                            
                            Spacer(modifier = Modifier.width(8.dp))
                            
                            Text(
                                text = "Test ESP32 Connection",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Continue Button
                Button(
                    onClick = onContinue,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFF10B981), // green-500
                                        Color(0xFF3B82F6)  // blue-600
                                    )
                                ),
                                RoundedCornerShape(16.dp)
                            )
                    ) {
                        Row(
                            modifier = Modifier.fillMaxSize(),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.ArrowForward,
                                contentDescription = "Continue Icon",
                                tint = Color.White,
                                modifier = Modifier.size(24.dp)
                            )
                            
                            Spacer(modifier = Modifier.width(8.dp))
                            
                            Text(
                                text = "Continue to Key Exchange",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )
                        }
                    }
                }
            } else {
                    // Connection Status Card
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                        ),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(20.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Icon(
                                imageVector = Icons.Default.Router,
                                contentDescription = "Fusion Node",
                                tint = Color(0xFFFBBF24), // yellow-400
                                modifier = Modifier.size(32.dp)
                            )
                            
                            Spacer(modifier = Modifier.height(12.dp))
                            
                            Text(
                                text = "Waiting for Fusion Node",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color(0xFFFBBF24) // yellow-400
                            )
                            
                            Spacer(modifier = Modifier.height(8.dp))
                            
                            Text(
                                text = "Listening for node ID from fusion node...",
                                fontSize = 14.sp,
                                color = Color(0xFF9CA3AF), // gray-400
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(32.dp))
            
            // Continue Button
            Button(
                onClick = onContinue,
                enabled = receivedNodeId != null,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (receivedNodeId != null) {
                        Color(0xFF10B981) // green-500
                    } else {
                        Color(0xFF6B7280) // gray-500
                    }
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Text(
                    text = if (receivedNodeId != null) "Continue to Key Exchange" else "Waiting for Node ID...",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White
                )
            }
        }
    }


// Manual Key Input Screen
@Composable
fun ManualKeyInputScreen(
    onContinue: () -> Unit,
    viewModel: SecureChatViewModel
) {
    val context = LocalContext.current
    var peerPublicKey by remember { mutableStateOf("") }
    var peerFusionNodeId by remember { mutableStateOf("") }
    
    // Get current device's public key and fusion node ID from ViewModel
    val currentPublicKey by viewModel.publicKey.collectAsState()
    val currentFusionNodeId by viewModel.connectedFusionNode.collectAsState()
    
    // Debug: Log fusion node ID changes
    LaunchedEffect(currentFusionNodeId) {
        Log.d("ManualKeyInputScreen", "Fusion Node ID changed: $currentFusionNodeId")
    }
    
    // Ensure fusion node ID is preserved when screen is displayed
    LaunchedEffect(Unit) {
        Log.d("ManualKeyInputScreen", "Screen displayed, checking fusion node ID")
        viewModel.ensureFusionNodeIdPreserved()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF1E40AF), // blue-900
                        Color(0xFF3730A3), // indigo-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(RoundedCornerShape(40.dp))
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    Color(0xFF22D3EE), // cyan-400
                                    Color(0xFFA855F7)  // purple-500
                                )
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.VpnKey,
                        contentDescription = "Key Exchange Icon",
                        tint = Color.White,
                        modifier = Modifier.size(40.dp)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Manual Key Exchange",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Enter your peer's public key and fusion node ID",
                    fontSize = 16.sp,
                    color = Color(0xFFBFDBFE) // blue-200
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Your Device Information Card
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF064E3B).copy(alpha = 0.8f) // green-900/80
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "Your Device Information",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF34D399) // green-400
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Your Public Key
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Your Public Key",
                            fontSize = 14.sp,
                            color = Color(0xFF9CA3AF), // gray-400
                            fontWeight = FontWeight.Medium
                        )
                        
                        Spacer(modifier = Modifier.height(4.dp))
                             
                        Text(
                            text = if (currentPublicKey != null) {
                                val publicKeyBytes = currentPublicKey!!.public.encoded
                                val publicKeyHex = publicKeyBytes.take(16).joinToString("") { "%02x".format(it) }
                                "pk_$publicKeyHex"
                            } else {
                                "Generating..."
                            },
                            fontSize = 12.sp,
                            color = Color.White,
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(8.dp)
                                .background(
                                    Color(0xFF374151), // gray-800
                                    RoundedCornerShape(8.dp)
                                )
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        // Copy Public Key Button
                        Button(
                            onClick = {
                                if (currentPublicKey != null) {
                                    val publicKeyBytes = currentPublicKey!!.public.encoded
                                    val publicKeyHex = publicKeyBytes.take(16).joinToString("") { "%02x".format(it) }
                                    val publicKeyString = "pk_$publicKeyHex"
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = ClipData.newPlainText("Public Key", publicKeyString)
                                    clipboard.setPrimaryClip(clip)
                                    Toast.makeText(context, "Public key copied to clipboard", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(context, "Public key not ready yet", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(36.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(
                                        Brush.horizontalGradient(
                                            colors = listOf(
                                                Color(0xFF34D399), // green-500
                                                Color(0xFF3B82F6)  // blue-500
                                            )
                                        ),
                                        RoundedCornerShape(8.dp)
                                    )
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxSize(),
                                    horizontalArrangement = Arrangement.Center,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.ContentCopy,
                                        contentDescription = "Copy Icon",
                                        tint = Color.White,
                                        modifier = Modifier.size(14.dp)
                                    )

                                    Spacer(modifier = Modifier.width(6.dp))

                                    Text(
                                        text = "Copy Public Key",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Color.White
                                    )
                                }
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Your Connected Fusion Node ID
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Connected Fusion Node ID",
                            fontSize = 14.sp,
                            color = Color(0xFF9CA3AF), // gray-400
                            fontWeight = FontWeight.Medium
                        )
                        
                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = currentFusionNodeId ?: "Not connected",
                            fontSize = 12.sp,
                            color = Color.White,
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(8.dp)
                                .background(
                                    Color(0xFF374151), // gray-800
                                    RoundedCornerShape(8.dp)
                                )
                        )
                        
                        // Debug: Show raw state value
                        Text(
                            text = "Debug: ViewModel state = '$currentFusionNodeId'",
                            fontSize = 10.sp,
                            color = Color(0xFFFBBF24), // yellow-400
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(4.dp)
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        // Copy Fusion Node ID Button
                        Button(
                            onClick = {
                                if (currentFusionNodeId != null) {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = ClipData.newPlainText("Fusion Node ID", currentFusionNodeId)
                                    clipboard.setPrimaryClip(clip)
                                    Toast.makeText(context, "Fusion node ID copied to clipboard", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(context, "No fusion node connected", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(36.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(
                                        Brush.horizontalGradient(
                                            colors = listOf(
                                                Color(0xFF34D399), // green-500
                                                Color(0xFF3B82F6)  // blue-500
                                            )
                                        ),
                                        RoundedCornerShape(8.dp)
                                    )
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxSize(),
                                    horizontalArrangement = Arrangement.Center,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.ContentCopy,
                                        contentDescription = "Copy Icon",
                                        tint = Color.White,
                                        modifier = Modifier.size(14.dp)
                                    )

                                    Spacer(modifier = Modifier.width(6.dp))

                                    Text(
                                        text = "Copy Node ID",
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Color.White
                                    )
                                }
                            }
                        }
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        // Refresh Fusion Node ID Button
                        Button(
                            onClick = {
                                viewModel.debugCurrentState()
                                viewModel.ensureFusionNodeIdPreserved()
                                Toast.makeText(context, "Refreshed fusion node state", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(32.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(
                                        Brush.horizontalGradient(
                                            colors = listOf(
                                                Color(0xFFF59E0B), // amber-500
                                                Color(0xFFEF4444)  // red-500
                                            )
                                        ),
                                        RoundedCornerShape(6.dp)
                                    )
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxSize(),
                                    horizontalArrangement = Arrangement.Center,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Refresh,
                                        contentDescription = "Refresh Icon",
                                        tint = Color.White,
                                        modifier = Modifier.size(12.dp)
                                    )

                                    Spacer(modifier = Modifier.width(4.dp))

                                    Text(
                                        text = "Refresh State",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Color.White
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Peer Input Fields Card
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp)
                ) {
                    Text(
                        text = "Enter Peer Device Information",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF34D399) // green-400
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Peer Public Key Input
                    Column(
                        horizontalAlignment = Alignment.Start
                    ) {
                        Text(
                            text = "Peer's Public Key",
                            fontSize = 14.sp,
                            color = Color(0xFF9CA3AF), // gray-400
                            fontWeight = FontWeight.Medium
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        OutlinedTextField(
                            value = peerPublicKey,
                            onValueChange = { peerPublicKey = it },
                            placeholder = {
                                Text(
                                    text = "Enter peer's public key...",
                                    color = Color(0xFF9CA3AF) // gray-400
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = Color(0xFF3B82F6), // blue-500
                                unfocusedBorderColor = Color(0xFF4B5563), // gray-600
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                cursorColor = Color(0xFFC084FC) // purple-400
                            ),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Peer Fusion Node ID Input
                    Column(
                        horizontalAlignment = Alignment.Start
                    ) {
                        Text(
                            text = "Peer's Fusion Node ID",
                            fontSize = 14.sp,
                            color = Color(0xFF9CA3AF), // gray-400
                            fontWeight = FontWeight.Medium
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        OutlinedTextField(
                            value = peerFusionNodeId,
                            onValueChange = { peerFusionNodeId = it },
                            placeholder = {
                                Text(
                                    text = "Enter peer's fusion node ID...",
                                    color = Color(0xFF9CA3AF) // gray-400
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = Color(0xFF3B82F6), // blue-500
                                unfocusedBorderColor = Color(0xFF4B5563), // gray-600
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                cursorColor = Color(0xFFC084FC) // purple-400
                            ),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(24.dp))

                    // Continue Button
                    Button(
                        onClick = onContinue,
                        enabled = peerPublicKey.isNotBlank() && peerFusionNodeId.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color.Transparent
                        ),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(
                                    if (peerPublicKey.isNotBlank() && peerFusionNodeId.isNotBlank()) {
                                        Brush.horizontalGradient(
                                            colors = listOf(
                                                Color(0xFF10B981), // green-500
                                                Color(0xFF3B82F6)  // blue-600
                                            )
                                        )
                                    } else {
                                        Brush.verticalGradient(
                                            colors = listOf(
                                                Color(0xFF4B5563), // gray-600
                                                Color(0xFF4B5563)  // gray-600
                                            )
                                        )
                                    },
                                    RoundedCornerShape(16.dp)
                                )
                        ) {
                            Row(
                                modifier = Modifier.fillMaxSize(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.ArrowForward,
                                    contentDescription = "Continue Icon",
                                    tint = Color.White,
                                    modifier = Modifier.size(24.dp)
                                )
                                
                                Spacer(modifier = Modifier.width(8.dp))
                                
                                Text(
                                    text = if (peerPublicKey.isNotBlank() && peerFusionNodeId.isNotBlank()) 
                                        "Continue to Key Generation" 
                                    else 
                                        "Enter Both Fields to Continue",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color.White
                                )
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Set Test Fusion Node ID Button (for debugging)
                    Button(
                        onClick = {
                            viewModel.setFusionNodeId("E32-S3-01")
                            Toast.makeText(context, "Set test fusion node ID", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(40.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color.Transparent
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(
                                    Brush.horizontalGradient(
                                        colors = listOf(
                                            Color(0xFF10B981), // green-500
                                            Color(0xFF3B82F6)  // blue-500
                                        )
                                    ),
                                    RoundedCornerShape(8.dp)
                                )
                        ) {
                            Row(
                                modifier = Modifier.fillMaxSize(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Check,
                                    contentDescription = "Set Test Icon",
                                    tint = Color.White,
                                    modifier = Modifier.size(16.dp)
                                )

                                Spacer(modifier = Modifier.width(8.dp))

                                Text(
                                    text = "Set Test Node ID (E32-S3-01)",
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color.White
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}


// Key Generation Screen
@Composable
fun KeyGenerationScreen(
    onContinue: () -> Unit,
    viewModel: SecureChatViewModel
) {
    val context = LocalContext.current
    var isGenerating by remember { mutableStateOf(false) }
    var generationProgress by remember { mutableStateOf(0f) }
    var sharedKey by remember { mutableStateOf<String?>(null) }
    var sessionKey by remember { mutableStateOf<String?>(null) }
    var payload by remember { mutableStateOf<String?>(null) }
    
    // Get current device's public key and fusion node ID from ViewModel
    val currentPublicKey by viewModel.publicKey.collectAsState()
    val currentFusionNodeId by viewModel.connectedFusionNode.collectAsState()
    
    // Start key generation when screen is displayed
    LaunchedEffect(Unit) {
        isGenerating = true
        
        // Generate Shared Key
        repeat(100) {
            delay(50)
            generationProgress = (it + 1) / 100f
        }
        val timestamp1 = System.currentTimeMillis()
        val randomBytes1 = ByteArray(32)
        java.util.Random().nextBytes(randomBytes1)
        sharedKey = "SHARED_${timestamp1}_${randomBytes1.joinToString("") { "%02x".format(it) }}"
        
        // Generate Session Key
        repeat(100) {
            delay(30)
            generationProgress = (it + 1) / 100f
        }
        val timestamp2 = System.currentTimeMillis()
        val randomBytes2 = ByteArray(24)
        java.util.Random().nextBytes(randomBytes2)
        sessionKey = "SESSION_${timestamp2}_${randomBytes2.joinToString("") { "%02x".format(it) }}"
        
        // Generate Payload
        repeat(100) {
            delay(20)
            generationProgress = (it + 1) / 100f
        }
        val timestamp3 = System.currentTimeMillis()
        val randomBytes3 = ByteArray(16)
        java.util.Random().nextBytes(randomBytes3)
        payload = "PAYLOAD_${timestamp3}_${randomBytes3.joinToString("") { "%02x".format(it) }}"
        
        isGenerating = false
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF1E40AF), // blue-900
                        Color(0xFF3730A3), // indigo-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(32.dp))
            
            // Header
            Column(
            horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
        ) {
            Box(
                modifier = Modifier
                    .size(80.dp)
                    .clip(RoundedCornerShape(40.dp))
                    .background(
                        Brush.horizontalGradient(
                            colors = listOf(
                                    Color(0xFF22D3EE), // cyan-400
                                    Color(0xFFA855F7)  // purple-500
                            )
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                    Icon(
                        imageVector = Icons.Default.VpnKey,
                        contentDescription = "Key Generation Icon",
                        tint = Color.White,
                        modifier = Modifier.size(40.dp)
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
            Text(
                    text = "Key Generation",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

                Spacer(modifier = Modifier.height(8.dp))

            Text(
                    text = "Generating shared, session, and payload keys",
                fontSize = 16.sp,
                    color = Color(0xFFBFDBFE) // blue-200
            )
            }

            Spacer(modifier = Modifier.height(32.dp))

            if (isGenerating) {
                // Generation Progress
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                        modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                        CircularProgressIndicator(
                            progress = generationProgress,
                            modifier = Modifier.size(80.dp),
                            color = Color(0xFF3B82F6), // blue-500
                            strokeWidth = 8.dp
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Text(
                            text = "Generating Keys...",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "${(generationProgress * 100).toInt()}% Complete",
                            fontSize = 14.sp,
                            color = Color(0xFF9CA3AF) // gray-400
                        )
                    }
                }
            } else {
                // Generated Keys Display
                Column(
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    // Shared Key
                    KeyDisplayCard(
                        title = "Shared Key",
                        key = sharedKey ?: "",
                        color = Color(0xFF10B981) // green-500
                    )
                    
                    // Session Key
                    KeyDisplayCard(
                        title = "Session Key",
                        key = sessionKey ?: "",
                        color = Color(0xFF3B82F6) // blue-500
                    )
                    
                    // Payload
                    KeyDisplayCard(
                        title = "Payload",
                        key = payload ?: "",
                        color = Color(0xFF8B5CF6) // violet-500
                    )
                }
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Continue Button
                Button(
                    onClick = onContinue,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFF10B981), // green-500
                                        Color(0xFF3B82F6)  // blue-600
                                    )
                                ),
                                RoundedCornerShape(16.dp)
                            )
                ) {
                    Row(
                            modifier = Modifier.fillMaxSize(),
                            horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                                imageVector = Icons.Default.ArrowForward,
                                contentDescription = "Continue Icon",
                            tint = Color.White,
                                modifier = Modifier.size(24.dp)
                        )
                            
                            Spacer(modifier = Modifier.width(8.dp))

                        Text(
                                text = "Continue to Chat",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )
                        }
                    }
                }
            }
        }
    }
}

// Key Display Card Component
@Composable
fun KeyDisplayCard(
    title: String,
    key: String,
    color: Color
) {
    val context = LocalContext.current
    
    Card(
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier.padding(20.dp)
        ) {
            Text(
                text = title,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = color
            )
            
            Spacer(modifier = Modifier.height(8.dp))

                        Text(
                text = key,
                fontSize = 12.sp,
                color = Color.White,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp)
                    .background(
                        Color(0xFF1F2937), // gray-800
                        RoundedCornerShape(8.dp)
                    )
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Copy Button
            Button(
                onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText(title, key)
                    clipboard.setPrimaryClip(clip)
                    Toast.makeText(context, "$title copied to clipboard", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(36.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent
                ),
                shape = RoundedCornerShape(8.dp)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.horizontalGradient(
                                colors = listOf(
                                    color,
                                    color.copy(alpha = 0.8f)
                                )
                            ),
                            RoundedCornerShape(8.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier.fillMaxSize(),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copy Icon",
                            tint = Color.White,
                            modifier = Modifier.size(14.dp)
                        )

                        Spacer(modifier = Modifier.width(6.dp))

                    Text(
                            text = "Copy $title",
                        fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

// Chat Screen
@Composable
fun ChatScreen(
    selectedDevice: DeviceInfo?,
    viewModel: SecureChatViewModel,
    onReset: () -> Unit
) {
    var messages by remember { mutableStateOf(listOf<ChatMessage>()) }
    var newMessage by remember { mutableStateOf("") }

    // Sample messages
    LaunchedEffect(Unit) {
        messages = listOf(
            ChatMessage("Hello! How are you?", "you", "12:30 PM", true),
            ChatMessage("I'm doing great! Thanks for asking.", "peer", "12:31 PM", true),
            ChatMessage("This is a secure encrypted message.", "you", "12:32 PM", true)
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF111827), // gray-900
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        // Header
        Card(
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
            ),
            shape = RoundedCornerShape(0.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(RoundedCornerShape(20.dp))
                            .background(Color(0xFF10B981)), // green-500
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.Message,
                            contentDescription = "Chat Icon",
                            tint = Color.White,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Column {
                        Text(
                            text = "Secure Chat",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .background(
                                        color = Color(0xFF34D399), // green-400
                                        shape = CircleShape
                                    )
                            )

                            Text(
                                text = "Connected via ${selectedDevice?.name ?: "Unknown Device"}",
                                fontSize = 12.sp,
                                color = Color(0xFF34D399) // green-400
                            )
                        }
                    }
                }

                IconButton(onClick = onReset) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close Chat",
                        tint = Color.White
                    )
                }
            }
        }

        // Messages
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            if (messages.isEmpty()) {
                item {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.Message,
                            contentDescription = "Empty Chat",
                            tint = Color(0xFF9CA3AF), // gray-400
                            modifier = Modifier
                                .size(48.dp)
                                .padding(bottom = 16.dp)
                        )

                        Text(
                            text = "Start your secure conversation",
                            fontSize = 16.sp,
                            color = Color(0xFF9CA3AF) // gray-400
                        )
                    }
                }
            } else {
                items(messages) { message ->
                    ChatMessageItem(message = message)
                }
            }
        }

        // Message Input
        Card(
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
            ),
            shape = RoundedCornerShape(0.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = newMessage,
                        onValueChange = { newMessage = it },
                        placeholder = {
                            Text(
                                text = "Type your encrypted message...",
                                color = Color(0xFF9CA3AF) // gray-400
                            )
                        },
                        modifier = Modifier.weight(1f),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFF3B82F6), // blue-500
                            unfocusedBorderColor = Color(0xFF4B5563), // gray-600
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White
                        ),
                        shape = RoundedCornerShape(12.dp),
                        singleLine = true
                    )

                    IconButton(
                        onClick = {
                            if (newMessage.isNotBlank()) {
                                messages = messages + ChatMessage(
                                    newMessage,
                                    "you",
                                    "12:30 PM",
                                    true
                                )
                                newMessage = ""
                            }
                        },
                        modifier = Modifier
                            .size(40.dp)
                            .background(
                                color = if (newMessage.isNotBlank()) Color(0xFF3B82F6) else Color(0xFF4B5563),
                                shape = RoundedCornerShape(10.dp)
                            )
                    ) {
                                                 Icon(
                             imageVector = Icons.AutoMirrored.Filled.Send,
                            contentDescription = "Send Message",
                            tint = Color.White,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "End-to-end encrypted via fusion node relay",
                    fontSize = 12.sp,
                    color = Color(0xFF9CA3AF), // gray-400
                    modifier = Modifier.align(Alignment.CenterHorizontally)
                )
            }
        }
    }
}

// Chat Message Item
@Composable
fun ChatMessageItem(message: ChatMessage) {
    val isFromUser = message.sender == "you"

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (isFromUser) Arrangement.End else Arrangement.Start
    ) {
        Card(
            modifier = Modifier.widthIn(max = 280.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isFromUser) Color(0xFF2563EB) else Color(0xFF4B5563) // blue-600 or gray-600
            ),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Text(
                    text = message.text,
                    fontSize = 14.sp,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(4.dp))

                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (message.encrypted) {
                        Icon(
                            imageVector = Icons.Default.VpnKey,
                            contentDescription = "Encrypted",
                            tint = Color.White.copy(alpha = 0.7f),
                            modifier = Modifier.size(12.dp)
                        )
                    }

                    Text(
                        text = message.timestamp,
                        fontSize = 12.sp,
                        color = Color.White.copy(alpha = 0.7f)
                    )
                }
            }
        }
    }
}

// Data class for chat messages
data class ChatMessage(
    val text: String,
    val sender: String,
    val timestamp: String,
    val encrypted: Boolean
)

// Connection Status Screen
@Composable
fun ConnectionStatusScreen(
    connectionType: String,
    connectionState: String,
    connectedDeviceInfo: DeviceInfo?,
    isCheckingConnection: Boolean,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onContinue: () -> Unit
) {
    val title = if (connectionType == "bluetooth") "Bluetooth Connection Status" else "Wi-Fi Connection Status"
    val icon = if (connectionType == "bluetooth") Icons.Default.Wifi else Icons.Default.Router
    val isConnected = connectionState == "connected"

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        if (isConnected) Color(0xFF064E3B) else Color(0xFF7C2D12), // green-900 or orange-900
                        if (isConnected) Color(0xFF1E40AF) else Color(0xFFDC2626), // blue-900 or red-600
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(RoundedCornerShape(40.dp))
                        .background(
                            if (isConnected) {
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFF34D399), // green-400
                                        Color(0xFF3B82F6)  // blue-500
                                    )
                                )
                            } else {
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFFFB923C), // orange-400
                                        Color(0xFFEF4444)  // red-500
                                    )
                                )
                            }
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    if (isCheckingConnection) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(40.dp),
                            color = Color.White,
                            strokeWidth = 4.dp
                        )
                    } else {
                        Icon(
                            imageVector = if (isConnected) Icons.Default.Check else Icons.Default.Close,
                            contentDescription = if (isConnected) "Connected" else "Not Connected",
                            tint = Color.White,
                            modifier = Modifier.size(40.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = title,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = if (isCheckingConnection) "Checking connection..." else if (isConnected) "Connection verified successfully!" else "No connection detected",
                    fontSize = 16.sp,
                    color = if (isConnected) Color(0xFFBBF7D0) else Color(0xFFFED7AA) // green-200 or orange-200
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Connection Status Card
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF374151).copy(alpha = 0.5f) // gray-800/50
                ),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp)
                ) {
                    Text(
                        text = "Connection Details:",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Medium,
                        color = if (isConnected) Color(0xFF34D399) else Color(0xFFFB923C) // green-400 or orange-400
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    if (isConnected && connectedDeviceInfo != null) {
                        // Connected device info
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(48.dp)
                                    .clip(RoundedCornerShape(24.dp))
                                    .background(
                                        if (connectionType == "bluetooth") Color(0xFF60A5FA) else Color(0xFFC084FC)
                                    ),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = icon,
                                    contentDescription = "Device Icon",
                                    tint = Color.White,
                                    modifier = Modifier.size(24.dp)
                                )
                            }

                            Column {
                                Text(
                                    text = connectedDeviceInfo.name,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color.White
                                )

                                Text(
                                    text = "${connectionType.replaceFirstChar { it.uppercase() }} • ${connectedDeviceInfo.signal}% signal",
                                    fontSize = 14.sp,
                                    color = Color(0xFF9CA3AF) // gray-400
                                )

                                Text(
                                    text = "Status: Connected",
                                    fontSize = 14.sp,
                                    color = Color(0xFF34D399) // green-400
                                )
                            }
                        }
                    } else {
                        // Not connected message
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Info,
                                contentDescription = "Info Icon",
                                tint = Color(0xFFFB923C), // orange-400
                                modifier = Modifier.size(24.dp)
                            )

                            Column {
                                Text(
                                    text = "No device connected",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color.White
                                )

                                Text(
                                    text = "Please connect to a $connectionType device or network first",
                                    fontSize = 14.sp,
                                    color = Color(0xFF9CA3AF) // gray-400
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Action Buttons
            if (isConnected) {
                // Continue button when connected
                Button(
                    onClick = onContinue,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFF10B981), // green-500
                                        Color(0xFF3B82F6)  // blue-600
                                    )
                                ),
                                RoundedCornerShape(16.dp)
                            )
                    ) {
                        Row(
                            modifier = Modifier.fillMaxSize(),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Check,
                                contentDescription = "Continue Icon",
                                tint = Color.White,
                                modifier = Modifier.size(24.dp)
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            Text(
                                text = "Continue to Next Step",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )
                        }
                    }
                }
            } else {
                // Retry and back buttons when not connected
                Column {
                    Button(
                        onClick = onRetry,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color.Transparent
                        ),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(
                                    Brush.horizontalGradient(
                                        colors = listOf(
                                            Color(0xFFFB923C), // orange-500
                                            Color(0xFFEF4444)  // red-600
                                        )
                                    ),
                                    RoundedCornerShape(16.dp)
                                )
                        ) {
                            Row(
                                modifier = Modifier.fillMaxSize(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Refresh,
                                    contentDescription = "Retry Icon",
                                    tint = Color.White,
                                    modifier = Modifier.size(24.dp)
                                )

                                Spacer(modifier = Modifier.width(8.dp))

                                Text(
                                    text = "Retry Connection Check",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = Color.White
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Warning message
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFF7C2D12).copy(alpha = 0.3f) // orange-900/30
                        ),
                        border = BorderStroke(
                            width = 1.dp,
                            color = Color(0xFFFB923C) // orange-400
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Icon(
                                imageVector = Icons.Default.Info,
                                contentDescription = "Warning Icon",
                                tint = Color(0xFFFB923C), // orange-400
                                modifier = Modifier.size(24.dp)
                            )

                            Text(
                                text = "Please connect to a $connectionType device or network before proceeding. You cannot move forward without an active connection.",
                                fontSize = 14.sp,
                                color = Color(0xFFFED7AA) // orange-200
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Back Button
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = Color.White
                ),
                border = BorderStroke(
                    width = 1.dp,
                    color = Color(0xFF4B5563) // gray-600
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Back to Connection Guide",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}


