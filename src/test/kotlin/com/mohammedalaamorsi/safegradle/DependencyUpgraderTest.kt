package com.mohammedalaamorsi.safegradle

import junit.framework.TestCase

class DependencyUpgraderTest : TestCase() {

    fun `test upgrades groovy single-quoted dependency`() {
        assertEquals(
            "implementation 'com.google.guava:guava:32.0.0-jre'",
            DependencyUpgrader.upgradeLine("implementation 'com.google.guava:guava:31.0-jre'", "32.0.0-jre")
        )
    }

    fun `test upgrades kotlin double-quoted dependency`() {
        assertEquals(
            """implementation("com.squareup.okhttp3:okhttp:4.11.0")""",
            DependencyUpgrader.upgradeLine("""implementation("com.squareup.okhttp3:okhttp:4.10.0")""", "4.11.0")
        )
    }

    fun `test upgrades toml inline dependency`() {
        assertEquals(
            """okhttp = "com.squareup.okhttp3:okhttp:4.11.0"""",
            DependencyUpgrader.upgradeLine("""okhttp = "com.squareup.okhttp3:okhttp:4.10.0"""", "4.11.0")
        )
    }

    fun `test upgrades toml table version`() {
        assertEquals(
            """okhttp = { module = "com.squareup.okhttp3:okhttp", version = "4.11.0" }""",
            DependencyUpgrader.upgradeLine(
                """okhttp = { module = "com.squareup.okhttp3:okhttp", version = "4.10.0" }""",
                "4.11.0"
            )
        )
    }

    fun `test does not touch version ref lines`() {
        assertNull(
            DependencyUpgrader.upgradeLine(
                """okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }""",
                "4.11.0"
            )
        )
    }

    fun `test does not touch interpolated versions`() {
        assertNull(
            DependencyUpgrader.upgradeLine(
                """implementation("com.squareup.okhttp3:okhttp:${'$'}okhttpVersion")""",
                "4.11.0"
            )
        )
    }

    fun `test returns null when already at fix version`() {
        assertNull(
            DependencyUpgrader.upgradeLine("implementation 'com.google.guava:guava:32.0.0-jre'", "32.0.0-jre")
        )
    }

    fun `test returns null when no dependency on line`() {
        assertNull(DependencyUpgrader.upgradeLine("plugins {", "1.0.0"))
    }
}
