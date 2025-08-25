package com.example.securecomm.network

import android.content.Context
import android.util.Log
import kotlinx.coroutines.runBlocking

/**
 * Test class to demonstrate communication verification functionality
 */
class CommunicationTest(private val context: Context) {
    
    companion object {
        private const val TAG = "CommunicationTest"
    }
    
    private val verifier = CommunicationVerifier(context)
    
    /**
     * Run a comprehensive communication test
     */
    fun runCommunicationTest(): String {
        return runBlocking {
            try {
                Log.d(TAG, "Starting communication test...")
                
                // Test with a simulated device
                val proofs = verifier.verifyCommunication(
                    deviceId = "TEST_DEVICE_001",
                    connectionType = "wifi",
                    deviceAddress = "192.168.1.100"
                )
                
                // Generate test report
                val report = buildString {
                    appendLine("=== COMMUNICATION TEST REPORT ===")
                    appendLine("Timestamp: ${java.util.Date()}")
                    appendLine("Device ID: TEST_DEVICE_001")
                    appendLine("Connection Type: WiFi")
                    appendLine("Device Address: 192.168.1.100")
                    appendLine()
                    
                    appendLine("Test Results:")
                    proofs.forEach { proof ->
                        val status = if (proof.success) "✅ PASS" else "❌ FAIL"
                        appendLine("$status - ${proof.proofType.name}: ${proof.proofData}")
                        proof.latency?.let { latency ->
                            appendLine("   Latency: ${latency}ms")
                        }
                        proof.errorMessage?.let { error ->
                            appendLine("   Error: $error")
                        }
                    }
                    
                    appendLine()
                    appendLine("Summary:")
                    appendLine(verifier.getCommunicationSummary())
                }
                
                Log.d(TAG, "Communication test completed")
                report
                
            } catch (e: Exception) {
                Log.e(TAG, "Communication test failed", e)
                "Communication test failed: ${e.message}"
            }
        }
    }
    
    /**
     * Test different connection types
     */
    fun testMultipleConnectionTypes(): String {
        return runBlocking {
            try {
                Log.d(TAG, "Starting multi-connection test...")
                
                val connectionTypes = listOf("wifi", "bluetooth")
                val results = mutableListOf<String>()
                
                for (connectionType in connectionTypes) {
                    val proofs = verifier.verifyCommunication(
                        deviceId = "TEST_DEVICE_002",
                        connectionType = connectionType
                    )
                    
                    val successCount = proofs.count { it.success }
                    val totalCount = proofs.size
                    val successRate = if (totalCount > 0) (successCount * 100.0 / totalCount).toInt() else 0
                    
                    results.add("$connectionType: $successRate% ($successCount/$totalCount tests passed)")
                }
                
                val report = buildString {
                    appendLine("=== MULTI-CONNECTION TEST REPORT ===")
                    appendLine("Timestamp: ${java.util.Date()}")
                    appendLine()
                    appendLine("Results:")
                    results.forEach { result ->
                        appendLine("• $result")
                    }
                }
                
                Log.d(TAG, "Multi-connection test completed")
                report
                
            } catch (e: Exception) {
                Log.e(TAG, "Multi-connection test failed", e)
                "Multi-connection test failed: ${e.message}"
            }
        }
    }
    
    /**
     * Test with different device scenarios
     */
    fun testDeviceScenarios(): String {
        return runBlocking {
            try {
                Log.d(TAG, "Starting device scenario test...")
                
                val scenarios = listOf(
                    Triple("NEARBY_DEVICE", "wifi", "192.168.1.101"),
                    Triple("FAR_DEVICE", "wifi", "10.0.0.100"),
                    Triple("BLE_DEVICE", "bluetooth", null),
                    Triple("UNKNOWN_DEVICE", "unknown", null)
                )
                
                val results = mutableListOf<String>()
                
                for ((deviceId, connectionType, address) in scenarios) {
                    val proofs = verifier.verifyCommunication(
                        deviceId = deviceId,
                        connectionType = connectionType,
                        deviceAddress = address
                    )
                    
                    val successCount = proofs.count { it.success }
                    val totalCount = proofs.size
                    val successRate = if (totalCount > 0) (successCount * 100.0 / totalCount).toInt() else 0
                    
                    results.add("$deviceId ($connectionType): $successRate% success rate")
                }
                
                val report = buildString {
                    appendLine("=== DEVICE SCENARIO TEST REPORT ===")
                    appendLine("Timestamp: ${java.util.Date()}")
                    appendLine()
                    appendLine("Scenario Results:")
                    results.forEach { result ->
                        appendLine("• $result")
                    }
                }
                
                Log.d(TAG, "Device scenario test completed")
                report
                
            } catch (e: Exception) {
                Log.e(TAG, "Device scenario test failed", e)
                "Device scenario test failed: ${e.message}"
            }
        }
    }
}
