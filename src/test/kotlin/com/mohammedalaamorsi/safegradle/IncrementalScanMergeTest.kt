package com.mohammedalaamorsi.safegradle

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class IncrementalScanMergeTest : BasePlatformTestCase() {

    private fun violation(file: com.intellij.openapi.vfs.VirtualFile, line: Int) = SecurityViolation(
        file = file, line = line, content = "x", message = "m", riskLevel = RiskLevel.LOW, checkId = "c"
    )

    fun `test merge replaces entries for rescanned files`() {
        val a = myFixture.configureByText("build.gradle", "a").virtualFile
        val b = myFixture.configureByText("settings.gradle", "b").virtualFile
        val existing = mapOf(a to listOf(violation(a, 1)), b to listOf(violation(b, 1)))

        val merged = IncrementalScan.merge(existing, mapOf(a to listOf(violation(a, 5), violation(a, 6))))

        assertEquals(2, merged[a]?.size)
        assertEquals(5, merged[a]?.first()?.line)
        assertEquals(1, merged[b]?.size)
    }

    fun `test merge drops files whose violations cleared`() {
        val a = myFixture.configureByText("build.gradle", "a").virtualFile
        val existing = mapOf(a to listOf(violation(a, 1)))

        val merged = IncrementalScan.merge(existing, mapOf(a to emptyList()))

        assertFalse(merged.containsKey(a))
    }

    fun `test merge adds newly violating files`() {
        val a = myFixture.configureByText("build.gradle", "a").virtualFile
        val b = myFixture.configureByText("settings.gradle", "b").virtualFile
        val existing = mapOf(a to listOf(violation(a, 1)))

        val merged = IncrementalScan.merge(existing, mapOf(b to listOf(violation(b, 2))))

        assertEquals(1, merged[a]?.size)
        assertEquals(1, merged[b]?.size)
    }
}
