package com.mohammedalaamorsi.safegradle

import junit.framework.TestCase

class SecurityScoreTest : TestCase() {

    fun `test zero issues is grade A`() {
        assertEquals("A", SecurityScore.grade(0, 0, 0))
    }

    fun `test few low and medium issues without high is grade B`() {
        assertEquals("B", SecurityScore.grade(0, 1, 2)) // weighted 4
        assertEquals("B", SecurityScore.grade(0, 0, 4)) // weighted 4
    }

    fun `test any high never grades better than C`() {
        assertEquals("C", SecurityScore.grade(1, 0, 0)) // weighted 5
    }

    fun `test moderate issues is grade C`() {
        assertEquals("C", SecurityScore.grade(0, 5, 0)) // weighted 10
        assertEquals("C", SecurityScore.grade(2, 0, 0)) // weighted 10
    }

    fun `test heavy issues is grade D`() {
        assertEquals("D", SecurityScore.grade(2, 2, 1)) // weighted 15
        assertEquals("D", SecurityScore.grade(4, 0, 0)) // weighted 20
    }

    fun `test severe issues is grade F`() {
        assertEquals("F", SecurityScore.grade(5, 0, 0)) // weighted 25
        assertEquals("F", SecurityScore.grade(0, 10, 1)) // weighted 21
    }

    fun `test weighted sums severities`() {
        assertEquals(0, SecurityScore.weighted(0, 0, 0))
        assertEquals(8, SecurityScore.weighted(1, 1, 1))
    }
}
