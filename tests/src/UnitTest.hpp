
#include <cstdio>

#include <api/api.hpp>
#include <test/Test.hpp>
#include <thread/Mutex.hpp>
#include <thread/Thread.hpp>
#include <thread/Cond.hpp>
#include <fs/DataFile.hpp>
#include <fs/ViewFile.hpp>

#include "inet/Socket.hpp"
#include "inet/Http.hpp"

using namespace chrono;
using namespace test;
using namespace thread;
using namespace inet;
using namespace fs;
using namespace var;
using namespace printer;


using S = Socket;

class UnitTest : public test::Test {

  Socket::Family m_family;
  u16 m_server_port;
  Mutex m_listening_mutex;
  Cond m_listening = Cond(m_listening_mutex);

  void randomize_server_port() {
    m_server_port = ClockTime::get_system_time().nanoseconds() / 1000;
    m_server_port = (m_server_port % (65535 - 49152)) + 49152;
  }

  auto start_server(Thread::Function &&server_function) {
    m_listening.set_asserted(false);
    auto server_thread
      = Thread(std::forward<Thread::Function>(server_function));

    PRINTER_TRACE(printer(), "wait listening");
    while (!m_listening && server_thread.is_running()) {
      wait(25_milliseconds);
    }
    return server_thread;
  }

public:
  explicit UnitTest(var::StringView name) : test::Test(name) {}

  bool execute_class_api_case() override {

#if !defined __win32
    TEST_ASSERT_RESULT(socket_case());
    TEST_ASSERT_RESULT(socket_address_case());
#endif
    TEST_ASSERT_RESULT(http_client_case());

    return true;
  }

  auto http_server() {

    AddressInfo address_info(AddressInfo::Construct()
                               .set_family(S::Family::inet)
                               .set_service(NumberString(m_server_port))
                               .set_type(Socket::Type::stream)
                               .set_flags(AddressInfo::Flags::passive));

    TEST_ASSERT(address_info.list().count() > 0);

    const SocketAddress &server_listen_address = address_info.list().at(0);
    Socket server_listen_socket = Socket(server_listen_address)
                                    .set_option(SocketOption(
                                      Socket::Level::socket,
                                      Socket::NameFlags::socket_reuse_address))
                                    .bind_and_listen(server_listen_address)
                                    .move();

    SocketAddress accept_address;

    printer().object("listening", server_listen_address);
    m_listening.set_asserted();

    HttpServer(server_listen_socket.accept(accept_address))
      .run(
        [&](HttpServer *server, const Http::Request &request) -> Http::IsStop {
          printer().key(
            "requestMethod",
            Http::to_string(request.method()).string_view());

          const StringView hello_world = "Hello World";
          DataFile incoming;

          const bool is_connection_close
            = server->get_header_field("connection") == "close";

          printer().key("Connection", server->get_header_field("connection"));

          auto show_incoming = [&]() {
            auto incoming_copy = incoming.data();
            printer().key("incoming", incoming_copy.add_null_terminator());
          };

          switch (request.method()) {
          case Http::Method::null:
            server->receive(NullFile())
              .send(Http::Response(
                server->http_version(),
                Http::Status::bad_request));
            show_incoming();
            break;

          case Http::Method::get:
            server->receive(NullFile())
              .add_header_field(
                "content-length",
                NumberString(hello_world.length()))
              .send(Http::Response(server->http_version(), Http::Status::ok))
              .send(ViewFile(View(hello_world)));
            show_incoming();
            break;

          case Http::Method::post:
          case Http::Method::put:
            server->receive(incoming)
              .add_header_field("content-length", NumberString(incoming.size()))
              .send(Http::Response(server->http_version(), Http::Status::ok))
              .send(incoming.seek(0));
            show_incoming();
            break;

          case Http::Method::patch:
            server->receive(incoming)
              .add_header_field("content-length", NumberString(incoming.size()))
              .send(Http::Response(server->http_version(), Http::Status::ok))
              .send(incoming.seek(0));
            break;

          case Http::Method::delete_:
          case Http::Method::head:
          case Http::Method::options:
          case Http::Method::trace:
            break;
          }

          printer().key_bool("close", is_connection_close);
          return is_connection_close ? Http::IsStop::yes : Http::IsStop::no;
        });

    printer().key("connection", StringView("--close--"));
    return true;
  }

  bool http_client_case() {
    randomize_server_port();

    {
      m_listening.set_asserted(false);
      Printer::Object po(printer(), "httpClient/Server");
      auto server_thread = start_server([&]() -> void * {
        http_server();
        return nullptr;
      });
      TEST_ASSERT(is_success());

      PRINTER_TRACE(printer(), "httpGet");
      HttpClient http_client;
      http_client.connect("localhost", m_server_port);

      TEST_ASSERT(is_success());

      {
        auto response = Http::MethodResponse(DataFile());
        TEST_ASSERT(http_client.get("index.html", response).is_success());

        printer().key(
          "serverResponse",
          StringView(response.file.data().add_null_terminator()));
        TEST_ASSERT(
          StringView(response.file.data().add_null_terminator())
          == "Hello World");
      }

      {
        auto response = Http::MethodResponse(DataFile());
        TEST_ASSERT(http_client.get("index.html", response).is_success());

        printer().key(
          "serverResponse",
          StringView(response.file.data().add_null_terminator()));
        TEST_ASSERT(
          StringView(response.file.data().add_null_terminator())
          == "Hello World");
      }

      {

        Http::MethodExchange<DataFile> exchange(
          DataFile().write("Special Request").seek(0));

        TEST_ASSERT(http_client.post("index.html", exchange).is_success());

        printer().key(
          "request",
          View(exchange.request.data()).to_string<GeneralString>());
        printer().key(
          "response",
          View(exchange.response.data()).to_string<GeneralString>());

        TEST_ASSERT(exchange.request.data() == exchange.response.data());
      }

      {

        auto exchange
          = Http::MethodExchange(DataFile().write("Special Request").seek(0));
        TEST_ASSERT(http_client.post("index.html", exchange).is_success());

        printer().key(
          "request",
          View(exchange.request.data()).to_string<GeneralString>());
        printer().key(
          "response",
          View(exchange.response.data()).to_string<GeneralString>());

        TEST_ASSERT(exchange.request.data() == exchange.response.data());
      }

      {
        auto exchange = Http::MethodExchange(
          DataFile().write("Special Request Post").seek(0));
        TEST_ASSERT(http_client.post("index.html", exchange).is_success());

        printer().key(
          "request",
          View(exchange.request.data()).to_string<GeneralString>());
        printer().key(
          "response",
          View(exchange.response.data()).to_string<GeneralString>());

        TEST_ASSERT(exchange.request.data() == exchange.response.data());
      }

      {
        Printer::Object exchange_object(printer(), "exchange");
        auto exchange = Http::MethodExchange<DataFile>(
          DataFile().write(StringView("Special Request Post")).seek(0));

        printer().key("requestSize", NumberString(exchange.request.size()));

        TEST_ASSERT(http_client.add_header_field("connection", "close")
                      .post("index.html", exchange)
                      .is_success());

        printer().key(
          "request",
          View(exchange.request.data()).to_string<GeneralString>());
        printer().key(
          "response",
          View(exchange.response.data()).to_string<GeneralString>());

        TEST_ASSERT(exchange.request.data() == exchange.response.data());
      }

      wait(500_milliseconds);

      TEST_ASSERT(is_success());
    }

    {

      Printer::Object po(printer(), "http://httpbin.org/get");
      HttpClient http_client;

      printer().key("is", StringView("connecting"));
      TEST_ASSERT(http_client.connect("httpbin.org").is_success());

      {
        printer().key("is", StringView("getting"));
        auto response = Http::MethodResponse(DataFile());
        TEST_EXPECT(http_client.get("/get", response).is_success());
        printer().key("response", response.file.data().add_null_terminator());
      }

      {
        auto response = Http::MethodResponse(DataFile());
        printer().key("is", StringView("getting"));
        TEST_EXPECT(http_client.get("/get", response).is_success());
        printer().key("response", response.file.data().add_null_terminator());
      }

      {
        printer().key("is", StringView("putting"));
        auto exchange
          = Http::MethodRequest(DataFile().write("HelloWorld").seek(0));
        TEST_EXPECT(http_client.put("/put", exchange).is_success());
        printer().key("response", exchange.file.data().add_null_terminator());
      }

      {
        auto request = Http::MethodRequest<DataFile>(
          DataFile().write("HelloWorld").seek(0));
        printer().key("is", StringView("putting"));
        TEST_EXPECT(http_client.put("/put", request).is_success());
        printer().key("response", request.file.data().add_null_terminator());
      }
    }
    {
      Printer::Object po(printer(), "ip.jsontest.com");
      TEST_ASSERT(HttpClient()
                    .connect("ip.jsontest.com")
                    .get("/", Http::MethodResponse(NullFile()))
                    .is_success());

#if 0 && INET_API_IS_MBEDTLS
//https://ip.jsontest.com fails in firefox too
      {
        Printer::Object secure_object(printer(), "SecureClientCase");
        TEST_ASSERT(
          HttpSecureClient()
            .connect("ip.jsontest.com")
            .get("/", Http::ExecuteMethod().set_response(&(response.seek(0))))
            .is_success());
      }
#endif
    }

    {
      Printer::Object po(printer(), "https://httpbin.org/redirect");

      HttpClient http_client;
      TEST_ASSERT(http_client.connect("httpbin.org").is_success());
      {
        auto response = Http::MethodResponse(DataFile());
        TEST_ASSERT(
          http_client.set_follow_redirects(false)
            .get("/redirect-to?url=httpbin.org&status_code=200", response)
            .is_success());

        const auto location = http_client.get_header_field("location");
        TEST_EXPECT(location == "httpbin.org");
        printer().key("location", location);
        if (response.file.size()) {
          printer().key("response", response.file.data().add_null_terminator());
        }
      }
      return true;
    }

#if INET_API_IS_MBEDTLS
    {
      Printer::Object po(printer(), "https://httpbin.org/get");
      HttpSecureClient http_client;

      TEST_ASSERT(http_client.connect("httpbin.org").is_success());

      {
        auto response = Http::MethodResponse(DataFile());
        TEST_ASSERT(http_client.get("/get", response).is_success());
        if (response.file.size()) {
          printer().key("response", response.file.data().add_null_terminator());
        }
      }
    }

    {
      // https://github.com/StratifyLabs/StratifyAPI/blob/master/src/inet/Socket.cpp

      Printer::Object po(printer(), "https://github.com");
      HttpSecureClient http_client;

      TEST_ASSERT(http_client.connect("github.com").is_success());

      {
        auto response = Http::MethodResponse(DataFile());
        TEST_ASSERT(
          http_client
            .get(
              "/StratifyLabs/StratifyAPI/blob/master/src/inet/Socket.cpp",
              response)
            .is_success());
        TEST_ASSERT(response.file.size() > 0);
      }
    }

    return true;
#endif
  }

  bool socket_address_case() {

    printer::Printer::Object po(printer(), "socketAddress");
    TEST_ASSERT(SocketAddress4().family() == S::Family::inet);
    TEST_ASSERT(SocketAddress6().family() == S::Family::inet6);

    TEST_ASSERT(
      SocketAddress4().set_protocol(S::Protocol::raw).protocol()
      == S::Protocol::raw);

    TEST_ASSERT(
      SocketAddress4().set_protocol(S::Protocol::ip).protocol()
      == S::Protocol::ip);

    TEST_ASSERT(
      SocketAddress4().set_protocol(S::Protocol::udp).protocol()
      == S::Protocol::udp);

    TEST_ASSERT(
      SocketAddress4().set_protocol(S::Protocol::tcp).protocol()
      == S::Protocol::tcp);

    TEST_ASSERT(
      SocketAddress4().set_address(IpAddress4("1.0.0.127")).get_address_string()
      == "1.0.0.127");

    TEST_ASSERT(
      SocketAddress4().set_address(IpAddress4(0)).get_address_string()
      == "0.0.0.0");
    printer().key(
      "address",
      SocketAddress4()
        .set_address(IpAddress4(0x12345678))
        .get_address_string()
        .string_view());
    TEST_ASSERT(
      SocketAddress4().set_address(IpAddress4(0x12345678)).get_address_string()
      == "18.52.86.120");

    TEST_ASSERT(SocketAddress4().set_port(3000).port() == 3000);
    TEST_ASSERT(SocketAddress6().set_port(3000).port() == 3000);

    TEST_ASSERT(
      SocketAddress6().set_protocol(S::Protocol::raw).protocol()
      == S::Protocol::raw);

    TEST_ASSERT(
      SocketAddress6().set_protocol(S::Protocol::ip).protocol()
      == S::Protocol::ip);

    TEST_ASSERT(
      SocketAddress6().set_protocol(S::Protocol::udp).protocol()
      == S::Protocol::udp);

    TEST_ASSERT(
      SocketAddress6().set_protocol(S::Protocol::tcp).protocol()
      == S::Protocol::tcp);

    printer().key(
      "address6",
      SocketAddress6()
        .set_address(IpAddress6("12:34:56:78:ab:cd:ef:01"))
        .get_address_string()
        .string_view());
    TEST_ASSERT(
      SocketAddress6()
        .set_address(IpAddress6("12:34:56:78:ab:cd:ef:01"))
        .get_address_string()
      == "0012:0034:0056:0078:00ab:00cd:00ef:0001");

    return true;
  }

  bool socket_case() {

    if (!socket_tcp_reflection_case(S::Family::inet)) {
      return false;
    }

    if (!socket_tcp_reflection_case(S::Family::inet6)) {
      return false;
    }

    if (!socket_tcp_reflection_case(S::Family::unspecified)) {
      return false;
    }

    if (!socket_udp_reflection_case(S::Family::inet)) {
      return false;
    }

    if (!socket_udp_reflection_case(S::Family::inet6)) {
      return false;
    }

    if (!socket_udp_reflection_case(S::Family::unspecified)) {
      return false;
    }

    return true;
  }

  bool socket_tcp_server() {

    AddressInfo address_info(AddressInfo::Construct()
                               .set_family(m_family)
                               .set_node("")
                               .set_service(NumberString(m_server_port))
                               .set_type(Socket::Type::stream)
                               .set_protocol(Socket::Protocol::tcp)
                               .set_flags(AddressInfo::Flags::passive));

    printer().object("tcpAddress", address_info);

    TEST_ASSERT(address_info.list().count() > 0);

    const SocketAddress &server_address = address_info.list().at(0);
    Socket server
      = std::move(Socket(server_address.family(), server_address.type())
                    .set_option(SocketOption(
                      S::Level::socket,
                      S::NameFlags::socket_reuse_address,
                      true)));
    // api::ExecutionContext::reset_error();
    TEST_ASSERT(is_success());

    printer().object("serverAddress", address_info.list().at(0));
    TEST_ASSERT(server.bind_and_listen(server_address).is_success());
    SocketAddress accept_address;
    m_listening.set_asserted();
    printer().key_bool("listening", bool(m_listening));
    Socket incoming = server.accept(accept_address);
    TEST_ASSERT(is_success());

    // data for incoming header
    var::Data incoming_data(64);

    // echo incoming data
    incoming.read(incoming_data)
      .write(View(incoming_data).truncate(return_value()));

    return true;
  }

  bool socket_tcp_reflection_case(Socket::Family family) {

    randomize_server_port();

    m_family = family;

    auto server_thread = start_server([&]() -> void * {
      socket_tcp_server();
      return nullptr;
    });

    TEST_ASSERT(server_thread.is_running());

    PRINTER_TRACE(printer(), "get address info");
    AddressInfo address_info(AddressInfo::Construct()
                               .set_family(AddressInfo::Family::inet)
                               .set_node("localhost")
                               .set_service(NumberString(m_server_port))
                               .set_type(Socket::Type::stream)
                               .set_flags(AddressInfo::Flags::passive));

    TEST_ASSERT(address_info.list().count() > 0);
    Socket socket(address_info.list().at(0));

    PRINTER_TRACE(printer(), "connect");
    TEST_ASSERT(socket.connect(address_info.list().at(0)).is_success());

    const StringView outgoing = "hello";
    Data incoming_data(64);
    TEST_ASSERT(socket.write(View(outgoing)).read(incoming_data).is_success());
    PRINTER_TRACE(
      printer(),
      "incoming " + String(View(incoming_data).truncate(return_value())));
    TEST_ASSERT(View(incoming_data).truncate(return_value()) == View(outgoing));
    PRINTER_TRACE(printer(), "done");
    return true;
  }

  auto socket_udp_server() {

    auto bind_socket = [&]() {
      AddressInfo address_info(AddressInfo::Construct()
                                 .set_family(m_family)
                                 .set_node("")
                                 .set_service(NumberString(m_server_port))
                                 .set_type(Socket::Type::datagram)
                                 .set_flags(AddressInfo::Flags::passive));

      printer().object("udpAddressInfo", address_info);

      for (const auto &a : address_info.list()) {
        Socket socket = std::move(Socket(a).bind(a));
        if (is_success()) {
          return socket;
        }

        API_RESET_ERROR();
      }

      API_RETURN_VALUE_ASSIGN_ERROR(std::move(Socket(m_family)), "", EINVAL);
    };

    Socket server_socket = bind_socket();
    SocketAddress server_address = server_socket.get_sock_name();

    printer().object("udpServerAddress", server_address);

    TEST_ASSERT(is_success());

    // data for incoming header
    var::Data incoming_data(64);

    PRINTER_TRACE(printer(), "udp server receive data");
    m_listening.set_asserted();
    // echo incoming data
    SocketAddress client_address = server_socket.receive_from(incoming_data);
    if (is_success()) {
      printer().object("clientAddress", client_address);
      server_socket.send_to(
        client_address,
        View(incoming_data).truncate(return_value()));
    }

    PRINTER_TRACE(printer(), "data received");
    return true;
  }

  bool socket_udp_reflection_case(Socket::Family family) {

    randomize_server_port();
    m_family = family;
    m_listening.set_asserted(false);

    auto server_thread = start_server([&]() -> void * {
      socket_udp_server();
      return nullptr;
    });
    TEST_ASSERT(server_thread.is_running());

    PRINTER_TRACE(printer(), "get address info");
    AddressInfo address_info(AddressInfo::Construct()
                               .set_family(AddressInfo::Family::inet)
                               .set_node("localhost")
                               .set_service(NumberString(m_server_port))
                               .set_type(Socket::Type::datagram)
                               .set_flags(AddressInfo::Flags::passive));

    TEST_ASSERT(address_info.list().count() > 0);
    Socket socket = std::move(Socket(address_info.list().at(0))
                                .set_option(SocketOption(
                                  S::Level::socket,
                                  S::NameFlags::socket_reuse_address,
                                  true)));

    const SocketAddress &address = address_info.list().at(0);

    const StringView outgoing = "hello";
    Data incoming_data(64);
    printer().object("udpSendToAddress", address);

    printer().key_bool("udpProtocol", address.protocol() == S::Protocol::udp);

    SocketAddress server_address
      = socket.send_to(address, View(outgoing)).receive_from(incoming_data);

    TEST_ASSERT(is_success());
    printer().object("serverAddress", server_address);
    PRINTER_TRACE(
      printer(),
      "incoming " + String(View(incoming_data).truncate(return_value())));
    TEST_ASSERT(View(incoming_data).truncate(return_value()) == View(outgoing));
    PRINTER_TRACE(printer(), "done");
    return true;
  }

};
