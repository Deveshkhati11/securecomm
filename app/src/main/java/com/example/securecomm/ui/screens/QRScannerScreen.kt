package com.example.Securecomm.ui.screens

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.example.mine.utils.QRCodeScanner
import androidx.compose.runtime.collectAsState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QRScannerScreen(
    onQRCodeScanned: (String) -> Unit,
    onBack: () -> Unit,
    onReset: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        )
    }
    
    var qrScanner by remember { mutableStateOf<QRCodeScanner?>(null) }
    var previewView by remember { mutableStateOf<PreviewView?>(null) }
    
    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        hasCameraPermission = isGranted
        if (isGranted) {
            // Start scanning when permission is granted
            qrScanner?.startScanning()
        }
    }
    
    // Collect scanner states
    val isScanning by qrScanner?.isScanning?.collectAsState() ?: remember { mutableStateOf(false) }
    val scannedData by qrScanner?.scannedData?.collectAsState() ?: remember { mutableStateOf<String?>(null) }
    val errorMessage by qrScanner?.errorMessage?.collectAsState() ?: remember { mutableStateOf<String?>(null) }
    
    // Handle scanned QR code
    LaunchedEffect(scannedData) {
        scannedData?.let { qrData ->
            onQRCodeScanned(qrData)
        }
    }
    
    // Initialize scanner when permission is granted
    LaunchedEffect(hasCameraPermission) {
        if (hasCameraPermission && previewView != null) {
            qrScanner = QRCodeScanner(context, lifecycleOwner, previewView!!)
            qrScanner?.startScanning()
        }
    }
    
    // Cleanup on dispose
    DisposableEffect(lifecycleOwner) {
        onDispose {
            qrScanner?.cleanup()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF1E3A8A), // blue-900
                        Color(0xFF7C3AED), // purple-600
                        Color(0xFF000000)  // black
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                IconButton(onClick = onBack) {
                    Icon(
                        imageVector = Icons.Default.ArrowBack,
                        contentDescription = "Back",
                        tint = Color.White
                    )
                }
                
                Text(
                    text = "Scan QR Code",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                
                IconButton(onClick = onReset) {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = "Reset",
                        tint = Color.White
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Camera preview
            if (hasCameraPermission) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .border(
                            width = 2.dp,
                            color = Color.White,
                            shape = RoundedCornerShape(16.dp)
                        )
                ) {
                    AndroidView(
                        factory = { context ->
                            PreviewView(context).also { preview ->
                                previewView = preview
                                preview.scaleType = androidx.camera.view.PreviewView.ScaleType.FILL_CENTER
                            }
                        },
                        modifier = Modifier.fillMaxSize()
                    )
                    
                    // Scanning overlay
                    if (isScanning == true) {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            // Scanning frame
                            Box(
                                modifier = Modifier
                                    .size(250.dp)
                                    .border(
                                        width = 3.dp,
                                        color = Color(0xFF10B981), // emerald-500
                                        shape = RoundedCornerShape(16.dp)
                                    )
                            )
                            
                            // Corner indicators
                            // Top-left corner
                            Box(
                                modifier = Modifier
                                    .offset(x = (-125).dp, y = (-125).dp)
                                    .size(30.dp)
                                    .border(
                                        width = 4.dp,
                                        color = Color(0xFF10B981),
                                        shape = RoundedCornerShape(topStart = 16.dp)
                                    )
                            )
                            
                            // Top-right corner
                            Box(
                                modifier = Modifier
                                    .offset(x = 125.dp, y = (-125).dp)
                                    .size(30.dp)
                                    .border(
                                        width = 4.dp,
                                        color = Color(0xFF10B981),
                                        shape = RoundedCornerShape(topEnd = 16.dp)
                                    )
                            )
                            
                            // Bottom-left corner
                            Box(
                                modifier = Modifier
                                    .offset(x = (-125).dp, y = 125.dp)
                                    .size(30.dp)
                                    .border(
                                        width = 4.dp,
                                        color = Color(0xFF10B981),
                                        shape = RoundedCornerShape(bottomStart = 16.dp)
                                    )
                            )
                            
                            // Bottom-right corner
                            Box(
                                modifier = Modifier
                                    .offset(x = 125.dp, y = 125.dp)
                                    .size(30.dp)
                                    .border(
                                        width = 4.dp,
                                        color = Color(0xFF10B981),
                                        shape = RoundedCornerShape(bottomEnd = 16.dp)
                                    )
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Instructions
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF1F2937).copy(alpha = 0.3f)
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.QrCodeScanner,
                            contentDescription = "Scan",
                            tint = Color(0xFF10B981),
                            modifier = Modifier.size(32.dp)
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "Position the QR code within the frame",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color.White,
                            textAlign = TextAlign.Center
                        )
                        
                        Text(
                            text = "The camera will automatically detect and scan the QR code",
                            fontSize = 14.sp,
                            color = Color.Gray.copy(alpha = 0.8f),
                            textAlign = TextAlign.Center
                        )
                    }
                }
                
            } else {
                // Permission request
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF1F2937).copy(alpha = 0.3f)
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.CameraAlt,
                            contentDescription = "Camera",
                            tint = Color(0xFFF59E0B),
                            modifier = Modifier.size(64.dp)
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Text(
                            text = "Camera Permission Required",
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            textAlign = TextAlign.Center
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "To scan QR codes, this app needs access to your camera",
                            fontSize = 16.sp,
                            color = Color.Gray.copy(alpha = 0.8f),
                            textAlign = TextAlign.Center
                        )
                        
                        Spacer(modifier = Modifier.height(24.dp))
                        
                        Button(
                            onClick = {
                                permissionLauncher.launch(Manifest.permission.CAMERA)
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(48.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF10B981)
                            ),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.CameraAlt,
                                    contentDescription = "Grant Permission",
                                    tint = Color.White
                                )
                                Text(
                                    text = "Grant Camera Permission",
                                    color = Color.White,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                }
            }
            
            // Error message
            errorMessage?.let { error ->
                Spacer(modifier = Modifier.height(16.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFEF4444).copy(alpha = 0.2f)
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Error,
                            contentDescription = "Error",
                            tint = Color(0xFFEF4444)
                        )
                        Text(
                            text = error,
                            color = Color(0xFFEF4444),
                            fontSize = 14.sp
                        )
                    }
                }
            }
        }
    }
}

