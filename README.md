# InetAPI

`InetAPI` is an internet access API following the Stratify Labs [API framework](https://github.com/StratifyLabs/API).

It includes sub-projects which will build LWIP as well as pull and build mbedtls from the Github repository.

## How to Build

The `InetAPI` library is designed to be a CMake sub-project. To build, please use one of these projects:

- Desktop [Command Line Interface](https://github.com/StratifyLabs/cli)
- [Stratify OS on Nucleo-144](https://github.com/StratifyLabs/StratifyOS-Nucleo144)

## Usage

### Sockets

You can use a `Socket` or a `SecureSocket`. The latter uses `mbedtls` for secure connections. The Socket layer is a C++ wrapper for POSIX style sockets (works on Stratify OS, Windows, macOS and Linux).

```cpp
#include <inet.hpp>

//HTTP server with sockets
AddressInfo address_info(AddressInfo::Construct()
                              .set_family(Socket::Family::inet)
                              .set_service(NumberString(self->m_server_port))
                              .set_type(Socket::Type::stream)
                              .set_flags(AddressInfo::Flags::passive));

const SocketAddress &server_listen_address = address_info.list().at(0);
Socket server_listen_socket =
    Socket(server_listen_address)
        .set_option(SocketOption(Socket::Level::socket,
                                  Socket::NameFlags::socket_reuse_address))
        .bind_and_listen(server_listen_address)
        .move();
```

### HTTP Server

```cpp
#include <inet.hpp>

HttpServer(server_listen_socket.accept(accept_address))
      .run(this,
            [](HttpServer *server, void *context,
              const Http::Request &request) -> Http::IsStop {
              // handle the request

              const StringView hello_world = "Hello World";
              DataFile incoming;

              const bool is_connection_close =
                  server->get_header_field("CONNECTION") == "CLOSE";

              switch (request.method()) {
              case Http::Method::null:
                server->receive(NullFile())
                    .send(Http::Response(server->http_version(),
                                        Http::Status::bad_request));
                break;

              case Http::Method::get:
                server->receive(NullFile())
                    .add_header_field("content-length",
                                      NumberString(hello_world.length()))
                    .send(Http::Response(server->http_version(),
                                        Http::Status::ok))
                    .send(ViewFile(View(hello_world)));

                break;

              case Http::Method::post:
                server->receive(incoming)
                    .add_header_field("content-length",
                                      NumberString(incoming.size()))
                    .send(Http::Response(server->http_version(),
                                        Http::Status::ok))
                    .send(incoming.seek(0));

                break;

              case Http::Method::put:
                server->receive(incoming)
                    .add_header_field("content-length",
                                      NumberString(incoming.size()))
                    .send(Http::Response(server->http_version(),
                                        Http::Status::ok))
                    .send(incoming.seek(0));
                break;

              case Http::Method::patch:
                server->receive(incoming)
                    .add_header_field("content-length",
                                      NumberString(incoming.size()))
                    .send(Http::Response(server->http_version(),
                                        Http::Status::ok))
                    .send(incoming.seek(0));
                break;

              case Http::Method::delete_:
                break;
              case Http::Method::head:
                break;
              case Http::Method::options:
                break;
              case Http::Method::trace:
                break;
              }

              return is_connection_close ? Http::IsStop::yes
                                        : Http::IsStop::no;
            });
```

### Http Client

```cpp

#include <fs.hpp>
#include <inet.hpp>

DataFile response;
HttpClient().connect("httpbin.org")
                  .get("/get", Http::ExecuteMethod().set_response(&response));

```