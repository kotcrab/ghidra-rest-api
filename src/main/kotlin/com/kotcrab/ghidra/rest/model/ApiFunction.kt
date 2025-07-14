package com.kotcrab.ghidra.rest.model

import java.math.BigInteger

data class ApiFunction(
  val name: String,
  val returnTypePathName: String,
  val parameters: List<Parameter>,
  val hasVarArgs: Boolean,
  val entryPoint: BigInteger,
  val entryPointSpaceId: Int,
  val addressRanges: List<AddressRange>,
) {
  data class AddressRange(
    val minAddress: BigInteger,
    val minAddressSpaceId: Int,
    val maxAddress: BigInteger,
    val maxAddressSpaceId: Int,
  )

  data class Parameter(
    val ordinal: Int,
    val name: String,
    val dataTypePathName: String,
  )
}
