#### Version 2.5

- Fixed program memory read not checking size of the actually read memory.
- Added option to get program memory without Base64 encoding.

#### Version 2.4

- Added build for Ghidra 11.3.
- Struct and union types now also include undefined components in the member list.
  Use `?excludeUndefinedComponents=true` query param for the previous behavior.

#### Version 2.3.1

- Fix `void` data type was not assigned to the `BUILT_IN` kind.

#### Version 2.3

- Added build for Ghidra 11.2.
- JVM 21 is now required.
- Updated internal dependencies.

#### Version 2.2.1

- Fixed `memoryBlock.sourceName` not defaulting to empty string when null.

#### Version 2.2

- Added `symbol.namespace` field.
- Added build for Ghidra 11.1.2.
- When reading memory `length` param can be specified as hex or octal string.
- Improved error handling.

#### Version 2.1.1

- Added build for Ghidra 11.1.1.

#### Version 2.1

- Added `function.parameter[].name` field.
- Added `returnTypePathName` and `parameters` fields to the function prototype types.
- Memory block comment may be null (API will return it as empty string).
- Updated internal dependencies.

#### Version 2

- Breaking change: `symbol.offset` renamed to `symbol.address`.
- Added `GET /v1/functions` endpoint.
- Added `addressSpaceName` field to the memory block object.

#### Version 1

- Initial release.
