package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiSymbol
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Listing
import ghidra.program.model.symbol.SymbolTable
import kotlin.collections.List
import kotlin.sequences.asSequence

class SymbolMapper {
  fun map(symbolTable: SymbolTable, listing: Listing): List<ApiSymbol> {
    return symbolTable.getAllSymbols(false)
      .asSequence()
      .map {
        ApiSymbol(
          address = it.address.offsetAsBigInteger,
          addressSpaceId = it.address.addressSpace.spaceID,
          name = it.name,
          type = it.symbolType.toString(),
          global = it.isGlobal,
          primary = it.isPrimary,
          pinned = it.isPinned,
          externalEntryPoint = it.isExternalEntryPoint,
          source = it.source.toString(),
          namespace = it.parentNamespace.getName(true),
          preComment = listing.getComment(CodeUnit.PRE_COMMENT, it.address) ?: "",
          dataTypePathName = listing.getDataAt(it.address)?.dataType?.pathName
        )
      }
      .toList()
  }
}
