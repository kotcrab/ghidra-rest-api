package com.kotcrab.ghidra.rest.model

data class ApiSymbol(
  val offset: Long,
  val name: String,
  val type: String,
  val global: Boolean,
  val primary: Boolean,
  val pinned: Boolean,
  val externalEntryPoint: Boolean,
  val source: String,
  val preComment: String,
  val dataTypePathName: String?,
)
