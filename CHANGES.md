# Version 1.2.0

## New Features

- CMake streamlining

## Bug Fixes

- `IpAddress4` needs to take `StringView` as an argument rather than `String`.

# Version 1.1.0

## New Features

- Add method to get SSID name as a c-string
- Added support for out-of-build mbedtls file
- Added support for mbedtls ECC algorithms

## Bug Fixes

- Remove Stratify OS dependency of mbedtls desktop build
- Fixed an issue with case sensitivity in HTTP headers and how URL parses paths (14a7d4c680ebbcb7d626a866431ae23f4e221a60)

# Version 1.0

Initial stable release with support for LWIP 2.1.2 and mbedtls 2.16.
