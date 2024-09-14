package com.kotcrab.ghidra.rest.model

import java.math.BigInteger

data class ApiSymbol(
  val address: BigInteger,
  val name: String,
  val type: String,
  val global: Boolean,
  val primary: Boolean,
  val pinned: Boolean,
  val externalEntryPoint: Boolean,
  val source: String,
  val namespace: String,
  val preComment: String,
  val dataTypePathName: String?,
)
