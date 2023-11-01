ghidra-rest-api
===============

This extension adds read-only REST API to your Ghidra project.

## Installation

This extension is under development, precompiled builds are not yet available.
For now if you would like to use it you will need to build it on your own.
Keep in mind there might be breaking changes.

## Usage

After installing this extension enable the `RestApiPlugin` in the `Miscellaneous` plugins configuration window.
Then after opening program select `Start Rest API Server` from the `Tools` menu bar. The server will start on port `18489`.

The following endpoints are available:

- `GET /v1/symbols` - return all symbols from the current `Program`.
- `GET /v1/types` - return all types used in the current `Program`.

## Building

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `./gradlew buildExtension` - build extension, this will create a zip file in the `dist` directory.

The following commands require `GHIDRA_USER_DIR` environment variable, it must be set to your Ghidra user
directory, for example: `C:\Users\<user>\.ghidra\.ghidra_10.x_PUBLIC`.

- `./gradlew ghidraInstall` - build and install into Ghidra user directory
- `./gradlew ghidraInstallThenRun` - run `ghidraInstall` task then start Ghidra, useful for development
- `./gradlew ghidraInstallThenDebug` - run `ghidraInstall` task then start Ghidra in debug mode, useful for development

## License

Licensed under Apache License 2.0.
