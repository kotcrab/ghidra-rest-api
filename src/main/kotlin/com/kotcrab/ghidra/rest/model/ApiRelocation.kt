package com.kotcrab.ghidra.rest.model

import ghidra.program.model.reloc.Relocation
import java.math.BigInteger

data class ApiRelocation(
  val address: BigInteger,
  val addressSpaceId: Int,
  val status: Relocation.Status,
  val type: Int,
  val values: LongArray,
  val bytes: ByteArray?,
  val symbolName: String? = null
)
