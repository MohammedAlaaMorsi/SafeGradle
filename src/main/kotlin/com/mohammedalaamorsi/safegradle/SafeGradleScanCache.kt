package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.components.*
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

@Service(Service.Level.PROJECT)
@State(name = "SafeGradleScanCache", storages = [Storage("safegradle_cache.xml")])
class SafeGradleScanCache : PersistentStateComponent<SafeGradleScanCache.State> {
    
    data class State(
        var cacheEntries: MutableMap<String, CacheEntry> = mutableMapOf()
    )

    data class CacheEntry(
        var hash: String = "",
        var violations: List<CachedViolation> = emptyList()
    )

    data class CachedViolation(
        var line: Int = 0,
        var content: String = "",
        var message: String = "",
        var riskLevel: String = "",
        var checkId: String = ""
    )

    private var myState = State()

    override fun getState(): State = myState
    override fun loadState(state: State) {
        myState = state
    }

    fun getCachedViolations(file: VirtualFile): List<SecurityViolation>? {
        val entry = myState.cacheEntries[file.path] ?: return null
        if (entry.hash != file.modificationCount.toString()) return null
        
        return entry.violations.map { 
            SecurityViolation(
                file = file,
                line = it.line,
                content = it.content,
                message = it.message,
                riskLevel = RiskLevel.valueOf(it.riskLevel)
            )
        }
    }

    fun updateCache(file: VirtualFile, violations: List<SecurityViolation>) {
        val entry = CacheEntry(
            hash = file.modificationCount.toString(),
            violations = violations.map { 
                CachedViolation(
                    line = it.line,
                    content = it.content,
                    message = it.message,
                    riskLevel = it.riskLevel.name
                )
            }
        )
        myState.cacheEntries[file.path] = entry
    }

    companion object {
        fun getInstance(project: Project): SafeGradleScanCache = project.getService(SafeGradleScanCache::class.java)
    }
}
