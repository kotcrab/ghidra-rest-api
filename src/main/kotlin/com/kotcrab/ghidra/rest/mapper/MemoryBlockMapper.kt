package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiMemoryBlock
import ghidra.program.model.mem.Memory

class MemoryBlockMapper {
  fun map(memory: Memory): List<ApiMemoryBlock> {
    return memory.blocks.iterator().asSequence()
      .map {
        ApiMemoryBlock(
          name = it.name,
            comment = it.comment,
            sourceName = it.sourceName,
            start = it.start.offsetAsBigInteger,
            end = it.end.offsetAsBigInteger,
            size = it.sizeAsBigInteger,
            read = it.isRead,
            write = it.isWrite,
            execute = it.isExecute,
            volatile = it.isVolatile,
            overlay = it.isOverlay,
            initialized = it.isInitialized,
            mapped = it.isMapped,
            external = it.isExternalBlock,
            loaded = it.isLoaded,
            type = it.type,
        )
      }
      .toList()
  }
}
