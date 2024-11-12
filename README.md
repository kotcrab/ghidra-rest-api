ghidra-rest-api
===============

This extension adds read-only REST API to your Ghidra project.

## Installation

Download prebuilt package from the [Releases](https://github.com/kotcrab/ghidra-rest-api/releases) section. Select release which matches
your Ghidra version. Then in main Ghidra window:

1. Select `File -> Install Extensions`.
2. Press the green plus button.
3. Select downloaded ZIP.
4. Restart Ghidra.

## Usage

After installing this extension enable the `RestApiPlugin` in the `Miscellaneous` plugins configuration window.
Then after opening program select `Start Rest API Server` from the `Tools` menu bar. The server will start on port `18489`.
The port currently can only be changed by setting `GHIDRA_REST_API_PORT` environment variable.

### Endpoints

The following endpoints are available, they all return data from the current `Program`:

- `GET /v1/bookmarks` - returns all bookmarks.
- `GET /v1/memory-blocks` - returns all memory blocks.
- `GET /v1/memory?address={addressString}&length={length}` - returns program memory.
  - Note that the `addressString` can include the address space, e.g. `?address=segment_2::0x20` will
    return data from the `segment_2` space at offset 0x20.
- `GET /v1/relocations` - returns all relocations.
- `GET /v1/functions` - returns all functions.
- `GET /v1/symbols` - returns all symbols.
- `GET /v1/types` - returns all types used in program.
  - You can set optional query parameter `?excludeUndefinedComponents=true` to exclude undefined components in struct and union types.

To view the response model see classes [here](https://github.com/kotcrab/ghidra-rest-api/tree/master/src/main/kotlin/com/kotcrab/ghidra/rest/model).
The fields are usually mapped 1:1 from Ghidra's data, for now you will need to refer to the Ghidra docs for detailed explanation about each field.

If you have some usecase which requires access to other `Program` data then feel free to open issue describing what is needed.

## Building

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `./gradlew buildExtension` - build extension, this will create a zip file in the `dist` directory.

The following commands require `GHIDRA_USER_DIR` environment variable, it must be set to your Ghidra user
directory, for example: `C:\Users\<user>\AppData\Roaming\ghidra\ghidra_11.1_PUBLIC`.

- `./gradlew ghidraInstall` - build and install into Ghidra user directory (contents of `$GHIDRA_USER_DIR/Extensions/ghidra-rest-api` will be overwritten).
- `./gradlew ghidraInstallThenRun` - run `ghidraInstall` task then start Ghidra, useful for development.
- `./gradlew ghidraInstallThenDebug` - run `ghidraInstall` task then start Ghidra in debug mode, useful for development.

## License

Licensed under Apache License 2.0.
