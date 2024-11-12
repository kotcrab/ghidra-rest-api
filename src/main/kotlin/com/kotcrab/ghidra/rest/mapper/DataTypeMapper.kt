package com.kotcrab.ghidra.rest.mapper

import com.kotcrab.ghidra.rest.model.ApiType
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghidra.program.model.data.Enum

class DataTypeMapper {
  fun map(dtm: DataTypeManager, excludeUndefinedComponents: Boolean): List<ApiType> {
    return dtm.allDataTypes
      .asSequence()
      .filterNot { it is Pointer && it.dataType == null }
      .map { type ->
        val (kind, properties) = when (type) {
          is Enum -> {
            ApiType.Kind.ENUM to ApiType.EnumProperties(
              type.names.map { ApiType.EnumMember(it, type.getValue(it), type.getComment(it) ?: "") }
            )
          }
          is TypeDef -> ApiType.Kind.TYPEDEF to ApiType.TypedefProperties(type.dataType.pathName, type.baseDataType.pathName)
          is Pointer -> ApiType.Kind.POINTER to ApiType.PointerProperties(type.dataType.pathName)
          is Array -> ApiType.Kind.ARRAY to ApiType.ArrayProperties(type.dataType.pathName, type.elementLength, type.numElements)
          is Structure -> ApiType.Kind.STRUCTURE to ApiType.CompositeProperties(mapCompositeMembers(type, excludeUndefinedComponents))
          is Union -> ApiType.Kind.UNION to ApiType.CompositeProperties(mapCompositeMembers(type, excludeUndefinedComponents))
          is FunctionDefinition -> ApiType.Kind.FUNCTION_DEFINITION to mapFunctionDefinition(type)
          is AbstractIntegerDataType -> ApiType.Kind.BUILT_IN to ApiType.BuiltInProperties("integer")
          is AbstractFloatDataType -> ApiType.Kind.BUILT_IN to ApiType.BuiltInProperties("float")
          is AbstractStringDataType -> ApiType.Kind.BUILT_IN to ApiType.BuiltInProperties("string")
          is Undefined -> ApiType.Kind.BUILT_IN to ApiType.BuiltInProperties("undefined")
          is VoidDataType -> ApiType.Kind.BUILT_IN to ApiType.BuiltInProperties("void")
          else -> ApiType.Kind.UNKNOWN to null
        }
        ApiType(
          kind = kind,
          name = type.name,
          displayName = type.displayName,
          pathName = type.pathName,
          length = type.length,
          alignedLength = type.alignedLength,
          zeroLength = type.isZeroLength,
          notYetDefined = type.isNotYetDefined,
          description = type.description,
          properties = properties,
        )
      }
      .toList()
  }

  private fun mapFunctionDefinition(type: FunctionDefinition): ApiType.FunctionDefinitionProperties {
    return ApiType.FunctionDefinitionProperties(
      prototypeString = type.prototypeString,
      returnTypePathName = type.returnType.pathName,
      parameters = type.arguments.map {
        ApiType.FunctionDefinitionProperties.Parameter(
          ordinal = it.ordinal,
          name = it.name,
          dataTypePathName = it.dataType.pathName
        )
      }
    )
  }

  private fun mapCompositeMembers(composite: Composite, excludeUndefinedComponents: Boolean): List<ApiType.CompositeMember> {
    val components = when {
      excludeUndefinedComponents -> composite.definedComponents
      else -> composite.components
    }
    return components.map {
      ApiType.CompositeMember(
        fieldName = it.fieldName ?: it.defaultFieldName,
        ordinal = it.ordinal,
        offset = it.offset,
        length = it.length,
        typePathName = it.dataType.pathName,
        comment = it.comment ?: "",
      )
    }
      .sortedBy { it.ordinal }
  }
}
