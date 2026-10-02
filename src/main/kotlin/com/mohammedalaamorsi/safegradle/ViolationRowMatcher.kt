package com.mohammedalaamorsi.safegradle

/**
 * Pure filtering logic for the results table, kept out of the Swing layer so it can be unit tested.
 */
object ViolationRowMatcher {

    /**
     * Decides whether a row passes the severity toggles and the free-text search.
     *
     * When no severity toggle is selected, all severities pass (toggles act as an opt-in filter).
     * The text search is case-insensitive and matches against [rowText].
     */
    fun matches(
        risk: RiskLevel?,
        highOn: Boolean,
        mediumOn: Boolean,
        lowOn: Boolean,
        searchText: String,
        rowText: String
    ): Boolean {
        if (highOn || mediumOn || lowOn) {
            val pass = (highOn && risk == RiskLevel.HIGH) ||
                (mediumOn && risk == RiskLevel.MEDIUM) ||
                (lowOn && risk == RiskLevel.LOW)
            if (!pass) return false
        }

        val text = searchText.trim().lowercase()
        if (text.isNotEmpty() && !rowText.lowercase().contains(text)) return false

        return true
    }
}
