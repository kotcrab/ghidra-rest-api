package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiAddressSpace
import ghidra.program.model.address.AddressFactory
import ghidra.program.model.address.AddressSpace

class AddressSpaceMapper {
  fun map(addressFactory: AddressFactory): List<ApiAddressSpace> {
    return addressFactory.allAddressSpaces.map {
      ApiAddressSpace(
        id = it.spaceID,
        physicalSpaceId = it.physicalSpace.spaceID,
        default = addressFactory.defaultAddressSpace.spaceID == it.spaceID,
        type = mapType(it),
        name = it.name,
        size = it.size,
        addressableUnitSize = it.addressableUnitSize,
        pointerSize = it.pointerSize,
        mappedRegisters = it.hasMappedRegisters(),
        signedOffset = it.hasSignedOffset(),
        overlaySpace = it.isOverlaySpace,
        hashSpace = it.isHashSpace,
      )
    }
  }

  private fun mapType(addressSpace: AddressSpace): ApiAddressSpace.Type {
    return when {
      addressSpace.isLoadedMemorySpace -> ApiAddressSpace.Type.LOADED_MEMORY_SPACE
      addressSpace.isNonLoadedMemorySpace -> ApiAddressSpace.Type.NON_LOADED_MEMORY_SPACE
      addressSpace.isRegisterSpace -> ApiAddressSpace.Type.REGISTER_SPACE
      addressSpace.isVariableSpace -> ApiAddressSpace.Type.VARIABLE_SPACE
      addressSpace.isStackSpace -> ApiAddressSpace.Type.STACK_SPACE
      addressSpace.isExternalSpace -> ApiAddressSpace.Type.EXTERNAL_SPACE
      addressSpace.isUniqueSpace -> ApiAddressSpace.Type.UNIQUE_SPACE
      addressSpace.isConstantSpace -> ApiAddressSpace.Type.CONSTANT_SPACE
      // Note: hash space is type unknown (see AddressSpace source)
      else -> ApiAddressSpace.Type.UNKNOWN
    }
  }
}
