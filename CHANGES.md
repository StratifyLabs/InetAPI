# Version 1.5.2

## Bug Fixes

- Removed including `sos/api/wifi.h` and uses `sdk/api.h` instead
  - This changes requires using CMakeSDK v2.1.0 or greater
- Add version requirements

# Version 1.5.1

## Bug Fixes

- Fixed bug when including `Wifi.hpp` to include appropriate types

# Version 1.5.0

## New Features

- Migrate to `API` v1.6
- Update `HttpClient` APIs to combine data and method requests in one object
- Use `cmsdk2_` functions for build
- Deprecated unsafe Http request functions
- Added `rvalue` ref qualifier functions for Http requests

## Bug Fixes

- Minor fixes and improvements via clang-tidy
- Use `api::SystemResource` and `api::UniquePointer` for `inet::Socket` and `inet::SecureSocket`

# Version 1.4.0

## New Features

- Ported to use `CMakeSDK` version 2.0+
- Update `mbedtls` to version 2.28

## Bug Fixes

- Don't build `SecureSocket` if `mbedtls` is not built

# Version 1.3.0

## New Features

- Add `Http::get_pseudorandom_server_port()` to generate a random server port 
- Add `doxygen` file
- Change default user-agent to InetAPI
- Remove `coverage` builds
- Allow inclusion of `Wifi.hpp` on `link` builds if Stratify OS headers are available

## Bug Fixes

- Add method to disable following redirects to that redirect test can pass
- Rename cmake option `INET_API_IS_MBEDTLS` to `INET_API_IS_MBEDTLS`
- Rename cmake option `IS_LWIP` to `INET_API_IS_LWIP`
- Replace `c++` with `cpp` in markdown codeblock docs
- `IpAddress4` needs to take `StringView` as an argument rather than `String`.
- Remove printer output from `Sntp`

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

- Remove Stratify OS dependency of mbedtls desktop build
- Fixed an issue with case sensitivity in HTTP headers and how URL parses paths (14a7d4c680ebbcb7d626a866431ae23f4e221a60)
- Fixed

# Version 1.0

Initial stable release with support for LWIP 2.1.2 and mbedtls 2.16.
