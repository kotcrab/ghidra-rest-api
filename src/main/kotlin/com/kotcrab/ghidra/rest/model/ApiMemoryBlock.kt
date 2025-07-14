package com.kotcrab.ghidra.rest.model

import ghidra.program.model.mem.MemoryBlockType
import java.math.BigInteger

data class ApiMemoryBlock(
  val name: String,
  val comment: String,
  val sourceName: String,
  val addressSpaceName: String,
  val addressSpaceId: Int,
  val start: BigInteger,
  val end: BigInteger,
  val size: BigInteger,
  val read: Boolean,
  val write: Boolean,
  val execute: Boolean,
  val volatile: Boolean,
  val overlay: Boolean,
  val initialized: Boolean,
  val mapped: Boolean,
  val external: Boolean,
  val loaded: Boolean,
  val artificial: Boolean,
  val type: MemoryBlockType,
)
