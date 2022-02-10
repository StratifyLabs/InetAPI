# Version 1.3.0

## New Features

- None yet

# Version 1.2.0

## New Features

- CMake streamlining

## Bug Fixes

- `IpAddress4`/`IpAddress6` needs to take `StringView` as an argument rather than `String`.
- Fixed a bug with reading the ethernet driver using LWIP

# Version 1.1.0

## New Features

- Add method to get SSID name as a c-string
- Added support for out-of-build mbedtls file
- Added support for mbedtls ECC algorithms

## Bug Fixes

- Fixed an issue with case sensitivity in HTTP headers and how URL parses paths (14a7d4c680ebbcb7d626a866431ae23f4e221a60)
- Fixed

# Version 1.0

Initial stable release with support for LWIP 2.1.2 and mbedtls 2.16.
