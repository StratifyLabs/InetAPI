// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include "printer/Printer.hpp"

#include "inet/Socket.hpp"
#include "var.hpp"

#if defined __win32
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH
#endif

#if !defined INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

printer::Printer &
printer::operator<<(printer::Printer &printer, const inet::SocketAddress &a) {
  printer.key(
    "family",
    (a.family() == inet::Socket::Family::inet) ? StringView("inet")
                                               : StringView("inet6"));
  printer.key("port", NumberString(a.port()).string_view());
  printer.key("address", a.get_address_string().string_view());
  printer.key("canonName", a.canon_name());
  return printer;
}

printer::Printer &
printer::operator<<(printer::Printer &printer, const inet::AddressInfo &a) {
  u32 i = 0;
  for (const auto &entry : a.list()) {
    printer.object(NumberString(i++), entry);
  }
  return printer;
}

using namespace inet;

namespace {

int is_initialized = {};

int initialize() {
  if (is_initialized == 0) {

#if defined __win32
    WSADATA wsadata;
    // Initialize Winsock
    WSAStartup(MAKEWORD(1, 0), &wsadata);
    auto result = WSAStartup(wsadata.wHighVersion, &wsadata);
    if (result != 0) {
      // set_error_number(EPIPE);
      return -1;
    }
#endif
  }

  is_initialized++;
  return 0;
}

int finalize() {
  if (is_initialized > 0 && --is_initialized == 0) {
#if defined __win32
    WSACleanup();
#endif
  }
  return 0;
}

int decode_socket_return(long long int value) {
#if defined __win32
  switch (value) {
  case INVALID_SOCKET:
    // set error number
    return -1;
    // case SOCKET_ERROR:
    // set error number
    // return -1;
  default:
    return value;
  }
#else
  return value;
#endif
}

SOCKET_T open_socket(int family, int type, int protocol) {
  auto result = API_SYSTEM_CALL("socket", ::socket(family, type, protocol));
  return result;
}

int close_socket(SOCKET_T socket) {
  int result = 0;
  if (socket != Socket::SOCKET_INVALID) {
    result = decode_socket_return(
#if defined __win32
      closesocket(socket)
#else
      ::close(socket)
#endif
    );
  }
  return result;
}

} // namespace

AddressInfo::AddressInfo(const Construct &options) {
  API_RETURN_IF_ERROR();

  API_ASSERT(!options.service().is_empty() || !options.node().is_empty());

  const var::GeneralString node_string(options.node());
  const var::KeyString service_string(options.service());

  const char *service_cstring
    = service_string.is_empty() ? nullptr : service_string.cstring();

  const char *node_cstring
    = node_string.is_empty() ? nullptr : node_string.cstring();

  initialize();

  struct addrinfo address_info {};
  address_info.ai_family = static_cast<int>(options.family());
  address_info.ai_protocol = static_cast<int>(options.protocol());
  address_info.ai_socktype = static_cast<int>(options.type());
  address_info.ai_flags = static_cast<int>(options.flags());

  struct addrinfo *info_start;
  API_SYSTEM_CALL(
    "",
    getaddrinfo(node_cstring, service_cstring, &address_info, &info_start));

  API_RETURN_IF_ERROR();
  for (struct addrinfo *info = info_start; info != nullptr;
       info = info->ai_next) {
    m_list.push_back(SocketAddress(
                       info->ai_addr,
#if defined __win32 || __linux
                       info->ai_addr->sa_family == AF_INET
                         ? sizeof(struct sockaddr_in)
                         : sizeof(struct sockaddr_in6),
#else
                       info->ai_addr->sa_len,
#endif
                       info->ai_canonname)
                       .set_protocol(static_cast<Protocol>(info->ai_protocol))
                       .set_type(static_cast<Type>(info->ai_socktype)));
  }

  freeaddrinfo(info_start);
  finalize();
}

Socket::Socket() { initialize(); }

Socket::Socket(const SocketAddress &socket_address)
  : m_socket(
    open_socket(
      static_cast<int>(socket_address.family()),
      static_cast<int>(socket_address.type()),
      static_cast<int>(socket_address.protocol())),
    &deleter),
    m_family(socket_address.family()) {
  initialize();
  API_RETURN_IF_ERROR();
}

Socket::Socket(Domain domain, Type type, Protocol protocol)
  : m_socket(
    open_socket(
      static_cast<int>(domain),
      static_cast<int>(type),
      static_cast<int>(protocol)),
    &deleter),
    m_family(domain) {
  initialize();
  API_RETURN_IF_ERROR();
}

void Socket::deleter(SOCKET_T *socket) {
  close_socket(*socket);
  finalize();
}

const Socket &Socket::bind(const SocketAddress &address) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
    "",
    decode_socket_return(::bind(
      m_socket.value(),
      address.to_sockaddr(),
      static_cast<int>(address.length()))));
  return *this;
}

SocketAddress Socket::get_sock_name() const {
  API_RETURN_VALUE_IF_ERROR(SocketAddress());
  socket_address_union_t s = {0};
  socklen_t length = sizeof(s.sockaddr_in6);
  API_SYSTEM_CALL("", ::getsockname(m_socket.value(), &s.sockaddr, &length));
  s.size = length;
  return SocketAddress(s);
}

const Socket &
Socket::bind_and_listen(const SocketAddress &address, int backlog) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL("", interface_bind_and_listen(address, backlog));
  return *this;
}

int Socket::interface_bind_and_listen(const SocketAddress &address, int backlog)
  const {
  bind(address);
  API_RETURN_VALUE_IF_ERROR(-1);

  return decode_socket_return(::listen(m_socket.value(), backlog));
}

Socket Socket::accept(SocketAddress &address) const {
  Socket result;
  socklen_t len = sizeof(struct sockaddr_in6);
  address.m_sockaddr.size = len;

  result.m_socket = decode_socket_return(
    ::accept(m_socket.value(), &address.m_sockaddr.sockaddr, &len));

  address.m_sockaddr.size = len;
  return result;
}

const Socket &Socket::connect(const SocketAddress &address) const {
  // Connect to server.
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL("", interface_connect(address));
  return *this;
}

int Socket::interface_connect(const SocketAddress &address) const {
  return decode_socket_return(::connect(
    m_socket.value(),
    address.to_sockaddr(),
    static_cast<int>(address.length())));
}

int Socket::interface_read(void *buf, int nbyte) const {
  const int result = decode_socket_return(::recv(
    m_socket.value(),
#if defined __win32
    static_cast<char *>
#endif
    (buf),
    nbyte,
    static_cast<int>(message_flags())));

  return result;
}

int Socket::interface_write(const void *buf, int nbyte) const {
  return decode_socket_return(::send(
    m_socket.value(),
#if defined __win32
    static_cast<const char *>
#endif
    (buf),
    nbyte,
    static_cast<int>(message_flags())));
}

const Socket &Socket::send_to(
  const SocketAddress &socket_address,
  const void *buf,
  int nbyte) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
    "",
    decode_socket_return(::sendto(
      m_socket.value(),
      (const char *)buf,
      nbyte,
      0,
      socket_address.to_sockaddr(),
      socket_address.length())));
  return *this;
}

SocketAddress Socket::receive_from(void *buf, int nbyte) const {
  API_RETURN_VALUE_IF_ERROR(SocketAddress());
  socket_address_union_t sockaddr;
  socklen_t length = sizeof(sockaddr.sockaddr_in6);

  API_SYSTEM_CALL(
    "",
    decode_socket_return(::recvfrom(
      m_socket.value(),
      (char *)buf,
      nbyte,
      0,
      &sockaddr.sockaddr,
      &length)));
  sockaddr.size = length;

  return SocketAddress(sockaddr);
}

const Socket &Socket::shutdown(const fs::OpenMode how) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL("", interface_shutdown(how));
  return *this;
}

int Socket::interface_shutdown(const fs::OpenMode how) const {
  int socket_how = SHUT_RDWR;
  if (how.is_read_only()) {
    socket_how = SHUT_RD;
  } else if (how.is_write_only()) {
    socket_how = SHUT_WR;
  }
  return decode_socket_return(::shutdown(m_socket.value(), socket_how));
}

const Socket &Socket::set_option(const SocketOption &option) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
    "",
    decode_socket_return(::setsockopt(
      m_socket.value(),
      static_cast<int>(option.m_level),
      static_cast<int>(option.m_name),
#if defined __win32
      (const char *)
#endif
        (&option.m_value.integer),
      option.m_size)));
  return *this;
}
