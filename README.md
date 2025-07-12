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

The extension is now installed, but you still need to enable the plugin for the `CodeBrowser` tool.
To do that:

1. Open some file from your project (or press the `CodeBrowser` icon in the `Tool Chest`).
2. Ghidra should prompt you about finding new plugins.
3. Press `Yes` to configure them and enable the `RestApiPlugin`.

If Ghidra doesn't prompt you just select `File -> Configure` from the `CodeBrowser` menu bar,
then `Miscellaneous` and enable the `RestApiPlugin`.

## Usage

After enabling the plugin you can select `Start Rest API Server` from the `Tools` menu bar. The server will start on port `18489`.
The port currently can only be changed by setting `GHIDRA_REST_API_PORT` environment variable.

### Endpoints

The following endpoints are available, they all return data from the current `Program`:

- `GET /v1/bookmarks` - returns all bookmarks.
- `GET /v1/memory-blocks` - returns all memory blocks.
- `GET /v1/memory?address={addressString}&length={length}` - returns program memory.
  - Note that the `addressString` can include the address space, e.g. `?address=segment_2::0x20` will
    return data from the `segment_2` space at offset 0x20.
  - The address string is parsed as a hex number, even if the `0x` prefix is not specified.
  - Length is parsed as a decimal number by default, but you can specify `0x` to parse it as a hex number.
  - Returned data might be smaller than the requested length if it exceeds available memory.
  - The data is returned in JSON with Base64 encoding, you can specify query parameter `?format=raw` to
    get the bytes directly without any encoding.
- `GET /v1/relocations` - returns all relocations.
- `GET /v1/functions` - returns all functions.
- `GET /v1/symbols` - returns all symbols.
- `GET /v1/types` - returns all types used in program.
  - You can set optional query parameter `?excludeUndefinedComponents=true` to exclude undefined components in struct and union types.

To view the response model see classes [here](https://github.com/kotcrab/ghidra-rest-api/tree/master/src/main/kotlin/com/kotcrab/ghidra/rest/model).
The fields are usually mapped 1:1 from Ghidra's data, for now you will need to refer to the Ghidra docs for detailed explanation about each field.

If you have some usecase which requires access to other `Program` data then feel free to open issue describing what is needed.

## Use cases

Here are some use cases where and how this plugin is used:

- Struct viewer tool in the PPSSPP emulator uses symbols and types fetched through this plugin to visualize objects data in game memory.
  This can be very helpful when reverse engineering unknown types by combining static and dynamic analysis. This is how it looks:
  ![image](https://github.com/user-attachments/assets/3f8e962d-e1b5-4d07-82c3-6ff96cf3ace4)
  - See the implementation [here](https://github.com/hrydgard/ppsspp/blob/fd4809490bc4a3ab87956924d8c3debc4e7ffcc1/UI/ImDebugger/ImStructViewer.cpp).
<br/><br/>
- This plugin is used in the [mist](https://github.com/kotcrab/mist) symbolic execution engine to get symbol and types data from the
  executable. Thanks to it the code is simpler as there is no need to reimplement analysis Ghidra has already done, it also allows for quite
  unique workflow where types from Ghidra can be directly referenced when writing symbolic test cases.

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
