package com.mohammedalaamorsi.safegradle

/**
 * Project security grade derived from violation counts.
 *
 * Weighted score = 5×HIGH + 2×MEDIUM + 1×LOW.
 * A = 0, B = no HIGH and ≤ 4, C = ≤ 10, D = ≤ 20, F = above.
 */
object SecurityScore {

    const val FORMULA = "Grade from weighted score: 5×HIGH + 2×MEDIUM + 1×LOW (A=0, B≤4 no HIGH, C≤10, D≤20, F>20)"

    fun weighted(high: Int, medium: Int, low: Int): Int = 5 * high + 2 * medium + low

    fun grade(high: Int, medium: Int, low: Int): String {
        val score = weighted(high, medium, low)
        return when {
            score == 0 -> "A"
            high == 0 && score <= 4 -> "B"
            score <= 10 -> "C"
            score <= 20 -> "D"
            else -> "F"
        }
    }
}
