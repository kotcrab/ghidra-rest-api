package com.kotcrab.ghidra.rest.model

data class ApiAddressSpace(
  val id: Int,
  val physicalSpaceId: Int,
  val default: Boolean,
  val name: String,
  val size: Int,
  val addressableUnitSize: Int,
  val pointerSize: Int,
  val type: Type,
  val mappedRegisters: Boolean,
  val signedOffset: Boolean,
  val overlaySpace: Boolean,
  val hashSpace: Boolean,
) {
  enum class Type {
    LOADED_MEMORY_SPACE,
    NON_LOADED_MEMORY_SPACE,
    REGISTER_SPACE,
    VARIABLE_SPACE,
    STACK_SPACE,
    EXTERNAL_SPACE,
    UNIQUE_SPACE,
    CONSTANT_SPACE,
    UNKNOWN,
  }
}
