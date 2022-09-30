// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#if INET_API_IS_MBEDTLS
#include "inet/SecureSocket.hpp"

using namespace inet;

namespace {

SecureSocketApi &secure_socket_api() {
  static SecureSocketApi instance;
  return instance;
}

void *open_socket(int domain, int type, int protocol) {
  void *result;
  API_SYSTEM_CALL(
    "secure socket()",
    secure_socket_api()->socket(&result, domain, type, protocol));
  return result;
}

int close_socket(void *context) {
  int result = 0;
  if (context) {
    result = secure_socket_api()->close(&context);
  }
  return result;
}
} // namespace

SecureSocket::SecureSocket(Domain domain, Type type, Protocol protocol)
  : m_context(
    open_socket(
      static_cast<int>(domain),
      static_cast<int>(type),
      static_cast<int>(protocol)),
    &deleter) {
  API_RETURN_IF_ERROR();
  set_family(domain);
}

SecureSocket::SecureSocket(const SocketAddress &address)
  : m_context(
    open_socket(
      static_cast<int>(address.family()),
      static_cast<int>(address.type()),
      static_cast<int>(address.protocol())),
    &deleter) {
  API_RETURN_IF_ERROR();
  set_family(address.family());
}

void SecureSocket::deleter(void *context) { close_socket(context); }

int SecureSocket::interface_connect(const SocketAddress &address) const {
  int result;

  if (m_ticket.size() > 0) {
    result = secure_socket_api()->parse_ticket(
      m_context.get(),
      var::View(m_ticket).to_void(),
      m_ticket.size());
    if (result < 0) {
      printf("Ticket parse failed: 0x%X\n", result * -1);
    }
  }

  result = secure_socket_api()->connect(
    m_context.get(),
    address.to_sockaddr(),
    address.length(),
    address.canon_name().cstring());

#if 0
  if (m_ticket_lifetime_seconds && result == 0) {
    m_ticket.resize(2619);
    do {
      result = secure_socket_api()->write_ticket(
        m_context,
        m_ticket.data(),
        m_ticket.size(),
        m_ticket_lifetime_seconds);
#if 0
      if (result == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
        m_ticket.resize(m_ticket.size() + 64);
      }
#endif
    } while (
#if 1
      (result == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) &&
#endif
      (m_ticket.size() < 4096));

    if (result > 0) {
      m_ticket.resize(result);
    }
  }
#endif
  return result;
}

// already documented in inet::Socket
int SecureSocket::interface_bind_and_listen(
  const SocketAddress &address,
  int backlog) const {
  return -1;
}

int SecureSocket::interface_shutdown(const fs::OpenMode how) const {
  MCU_UNUSED_ARGUMENT(how);
  // this should call shutdown() to shutdown for either reading or writing
  // close() will still be called on deconstruction
  return 0;
}

int SecureSocket::interface_write(const void *buf, int nbyte) const {
  int bytes_written = 0;
  int result;
  do {
    result = secure_socket_api()->write(
      m_context.get(),
      (const u8 *)buf + bytes_written,
      nbyte - bytes_written);
    if (result > 0) {
      bytes_written += result;
    }
  } while (result > 0);
  if (result < 0 && bytes_written == 0) {
    return result;
  }
  return bytes_written;
}

int SecureSocket::interface_read(void *buf, int nbyte) const {
  int result = secure_socket_api()->read(m_context.get(), buf, nbyte);
  if (result < 0) {
    printf(
      "ss returned: %d (0x%04x) %p %p %d\n",
      result,
      result * -1,
      m_context.get(),
      buf,
      nbyte);
  }
  return result;
}

#else
int inet_api_no_mbedtls_no_warning{};
#endif
