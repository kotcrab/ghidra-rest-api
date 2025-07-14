package com.kotcrab.ghidra.rest.model

import java.math.BigInteger

data class ApiBookmark(
  val id: Long,
  val address: BigInteger,
  val addressSpaceId: Int,
  val type: String,
  val category: String,
  val comment: String,
)
