package com.mohammedalaamorsi.safegradle

import junit.framework.TestCase

class ViolationRowMatcherTest : TestCase() {

    fun `test no toggles selected shows all severities`() {
        for (risk in RiskLevel.values()) {
            assertTrue(ViolationRowMatcher.matches(risk, false, false, false, "", "row"))
        }
    }

    fun `test high toggle shows only high`() {
        assertTrue(ViolationRowMatcher.matches(RiskLevel.HIGH, true, false, false, "", "row"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.MEDIUM, true, false, false, "", "row"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.LOW, true, false, false, "", "row"))
    }

    fun `test medium toggle shows only medium`() {
        assertFalse(ViolationRowMatcher.matches(RiskLevel.HIGH, false, true, false, "", "row"))
        assertTrue(ViolationRowMatcher.matches(RiskLevel.MEDIUM, false, true, false, "", "row"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.LOW, false, true, false, "", "row"))
    }

    fun `test low toggle shows only low`() {
        assertFalse(ViolationRowMatcher.matches(RiskLevel.HIGH, false, false, true, "", "row"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.MEDIUM, false, false, true, "", "row"))
        assertTrue(ViolationRowMatcher.matches(RiskLevel.LOW, false, false, true, "", "row"))
    }

    fun `test combined toggles show both severities`() {
        assertTrue(ViolationRowMatcher.matches(RiskLevel.HIGH, true, false, true, "", "row"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.MEDIUM, true, false, true, "", "row"))
        assertTrue(ViolationRowMatcher.matches(RiskLevel.LOW, true, false, true, "", "row"))
    }

    fun `test unknown risk is hidden when any toggle is on`() {
        assertFalse(ViolationRowMatcher.matches(null, true, false, false, "", "row"))
        assertTrue(ViolationRowMatcher.matches(null, false, false, false, "", "row"))
    }

    fun `test text search is case insensitive`() {
        assertTrue(ViolationRowMatcher.matches(RiskLevel.HIGH, false, false, false, "HTTP", "uses http url"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.HIGH, false, false, false, "ftp", "uses http url"))
    }

    fun `test text search is trimmed`() {
        assertTrue(ViolationRowMatcher.matches(RiskLevel.HIGH, false, false, false, "  http  ", "uses http url"))
    }

    fun `test severity and text filters combine`() {
        assertTrue(ViolationRowMatcher.matches(RiskLevel.HIGH, true, false, false, "http", "uses http url"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.LOW, true, false, false, "http", "uses http url"))
        assertFalse(ViolationRowMatcher.matches(RiskLevel.HIGH, true, false, false, "ftp", "uses http url"))
    }

    fun `test risk level natural order matches severity order`() {
        // Table sorting relies on the enum's natural order: LOW < MEDIUM < HIGH.
        assertTrue(RiskLevel.LOW < RiskLevel.MEDIUM)
        assertTrue(RiskLevel.MEDIUM < RiskLevel.HIGH)
    }
}
