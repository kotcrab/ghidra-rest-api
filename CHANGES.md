#### Version 2.2.1
- Fixed `memoryBlock.sourceName` not defaulting to empty string when null

#### Version 2.2

- Added `symbol.namespace` field
- Added build for Ghidra 11.1.2
- When reading memory `length` param can be specified as hex or octal string
- Improved error handling

#### Version 2.1.1

- Added build for Ghidra 11.1.1

#### Version 2.1

- Added `function.parameter[].name` field
- Added `returnTypePathName` and `parameters` fields to the function prototype types
- Memory block comment may be null (API will return it as empty string)
- Updated internal dependencies

#### Version 2

- Breaking change: `symbol.offset` renamed to `symbol.address`
- Added `GET /v1/functions` endpoint
- Added `addressSpaceName` field to the memory block object

#### Version 1

- Initial release
