package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiRelocation
import ghidra.program.model.reloc.RelocationTable

class RelocationMapper {
  fun map(relocationTable: RelocationTable): List<ApiRelocation> {
    return relocationTable.relocations.asSequence()
      .map {
        ApiRelocation(
          address = it.address.offsetAsBigInteger,
          addressSpaceId = it.address.addressSpace.spaceID,
          status = it.status,
          type = it.type,
          values = it.values,
          bytes = it.bytes,
          symbolName = it.symbolName
        )
      }
      .toList()
  }
}
