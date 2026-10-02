package com.mohammedalaamorsi.safegradle

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class BatchQuickFixEngineTest : BasePlatformTestCase() {

    private fun violation(
        fileName: String,
        checkId: String,
        message: String = "m",
        fixVersion: String? = null,
        content: String = "x"
    ) = SecurityViolation(
        file = myFixture.configureByText(fileName, content).virtualFile,
        line = 1,
        content = content,
        message = message,
        riskLevel = RiskLevel.MEDIUM,
        checkId = checkId,
        fixVersion = fixVersion
    )

    // ─── fixLine: HTTP → HTTPS ─────────────────────────────────────────────

    fun `test upgrades insecure http url to https`() {
        val line = """maven { url = uri("http://repo.internal/maven2") }"""
        val message = "Insecure HTTP URL 'http://repo.internal/maven2' — use HTTPS to prevent man-in-the-middle attacks."
        assertEquals(
            """maven { url = uri("https://repo.internal/maven2") }""",
            BatchQuickFixEngine.fixLine("network_activity", message, null, line)
        )
    }

    fun `test upgrades every http occurrence on the line`() {
        val line = """maven { url "http://a.internal"; mirror "http://b.internal" }"""
        val fixed = BatchQuickFixEngine.fixLine("network_activity", "Insecure HTTP URL", null, line)
        assertEquals("""maven { url "https://a.internal"; mirror "https://b.internal" }""", fixed)
    }

    fun `test returns null when line is already https`() {
        val line = """maven { url = uri("https://repo.maven.apache.org/maven2") }"""
        assertNull(BatchQuickFixEngine.fixLine("network_activity", "Insecure HTTP URL", null, line))
    }

    // ─── fixLine: jcenter → mavenCentral ───────────────────────────────────

    fun `test replaces jcenter with mavenCentral`() {
        val message = "JCenter (jcenter.bintray.com) was shut down in February 2022. Remove jcenter() and migrate to Maven Central."
        val fixed = BatchQuickFixEngine.fixLine("network_activity", message, null, "    jcenter()")
        assertEquals("    mavenCentral()", fixed)
    }

    fun `test replaces only the first jcenter on a line`() {
        val fixed = BatchQuickFixEngine.fixLine("network_activity", "JCenter", null, "jcenter() // jcenter() mirror")
        assertEquals("mavenCentral() // jcenter() mirror", fixed)
    }

    // ─── fixLine: dependency upgrade ───────────────────────────────────────

    fun `test upgrades vulnerable dependency to its fix version`() {
        val line = """implementation "org.apache.logging.log4j:log4j-core:2.14.1""""
        val fixed = BatchQuickFixEngine.fixLine("dependency_vulnerability", "CVE-2021-44228", "2.17.0", line)
        assertEquals("""implementation "org.apache.logging.log4j:log4j-core:2.17.0"""", fixed)
    }

    fun `test returns null for vulnerability without a fix version`() {
        val line = """implementation "org.apache.logging.log4j:log4j-core:2.14.1""""
        assertNull(BatchQuickFixEngine.fixLine("dependency_vulnerability", "no fix published yet", null, line))
    }

    fun `test returns null when dependency is already at the fix version`() {
        val line = """implementation "org.apache.logging.log4j:log4j-core:2.17.0""""
        assertNull(BatchQuickFixEngine.fixLine("dependency_vulnerability", "CVE-2021-44228", "2.17.0", line))
    }

    // ─── fixLine: unsupported checks ───────────────────────────────────────

    fun `test returns null for check without an automatic fix`() {
        val line = """repositories { maven { url "http://internal" } }"""
        assertNull(BatchQuickFixEngine.fixLine("shell_execution", "Runtime.getRuntime().exec(...)", null, line))
    }

    fun `test ignores http message from a different check`() {
        val line = """val url = "http://internal.example/repo""""
        assertNull(BatchQuickFixEngine.fixLine("file_exfiltration", "Insecure HTTP URL", null, line))
    }

    // ─── fixWrapper ───────────────────────────────────────────────────────

    fun `test appends checksum when the property is missing`() {
        val text = "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.2.1-bin.zip\n"
        assertEquals(
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.2.1-bin.zip\ndistributionSha256Sum=abc123\n",
            BatchQuickFixEngine.fixWrapper(text, "abc123")
        )
    }

    fun `test replaces an existing checksum`() {
        val text = "distributionUrl=x\ndistributionSha256Sum=oldvalue\n"
        assertEquals(
            "distributionUrl=x\ndistributionSha256Sum=abc123\n",
            BatchQuickFixEngine.fixWrapper(text, "abc123")
        )
    }

    fun `test adds a separator when the file has no trailing newline`() {
        assertEquals(
            "distributionUrl=x\ndistributionSha256Sum=abc123\n",
            BatchQuickFixEngine.fixWrapper("distributionUrl=x", "abc123")
        )
    }

    fun `test handles an empty wrapper file`() {
        assertEquals("distributionSha256Sum=abc123\n", BatchQuickFixEngine.fixWrapper("", "abc123"))
    }

    // ─── isFixable ────────────────────────────────────────────────────────

    fun `test http violation is fixable`() {
        val v = violation("build.gradle", "network_activity", "Insecure HTTP URL 'http://x'", content = """url = "http://x"""")
        assertTrue(BatchQuickFixEngine.isFixable(v))
    }

    fun `test wrapper violation is fixable only when a checksum is known`() {
        val fixable = violation("gradle-wrapper.properties", "gradle_wrapper_integrity", fixVersion = "abc123")
        val unknown = violation("gradle-wrapper.properties", "gradle_wrapper_integrity", fixVersion = null)
        assertTrue(BatchQuickFixEngine.isFixable(fixable))
        assertFalse(BatchQuickFixEngine.isFixable(unknown))
    }

    fun `test lockfile violations are never fixable`() {
        val v = violation(
            "gradle.lockfile", "dependency_vulnerability", fixVersion = "2.17.0",
            content = "org.apache.logging.log4j:log4j-core:2.14.1="
        )
        assertFalse(BatchQuickFixEngine.isFixable(v))
    }

    fun `test violations without an automatic fix are reported as not fixable`() {
        val v = violation("build.gradle", "shell_execution", content = """Runtime.getRuntime().exec("rm -rf /")""")
        assertFalse(BatchQuickFixEngine.isFixable(v))
    }
}
