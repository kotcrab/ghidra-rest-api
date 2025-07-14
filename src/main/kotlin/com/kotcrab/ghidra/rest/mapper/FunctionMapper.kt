package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiFunction
import ghidra.program.model.listing.FunctionManager
import kotlin.collections.List
import kotlin.collections.map
import kotlin.sequences.asSequence
import kotlin.sequences.map
import kotlin.sequences.toList

class FunctionMapper {
  fun map(functionManager: FunctionManager): List<ApiFunction> {
    return functionManager.getFunctions(false)
      .asSequence()
      .map { function ->
        ApiFunction(
          name = function.name,
          returnTypePathName = function.returnType.pathName,
          parameters = function.parameters.map {
            ApiFunction.Parameter(
              ordinal = it.ordinal,
              name = it.name,
              dataTypePathName = it.dataType.pathName
            )
          },
          hasVarArgs = function.hasVarArgs(),
          entryPoint = function.entryPoint.offsetAsBigInteger,
          entryPointSpaceId = function.entryPoint.addressSpace.spaceID,
          addressRanges = function.body.addressRanges.map {
            ApiFunction.AddressRange(
              minAddress = it.minAddress.offsetAsBigInteger,
              minAddressSpaceId = it.minAddress.addressSpace.spaceID,
              maxAddress = it.maxAddress.offsetAsBigInteger,
              maxAddressSpaceId = it.maxAddress.addressSpace.spaceID,
            )
          },
        )
      }
      .toList()
  }
}
