// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef SAPI_INET_SECURESOCKET_HPP_
#define SAPI_INET_SECURESOCKET_HPP_


#if INET_API_IS_MBEDTLS

#include <mbedtls_api.h>

#include <var/Data.hpp>

#include "Socket.hpp"

namespace inet {


using SecureSocketApi = api::Api<mbedtls_api_t, MBEDTLS_API_REQUEST>;

class SecureSocket : public Socket {
public:
  SecureSocket() = default;

  explicit SecureSocket(
    Domain domain,
    Type type = Type::stream,
    Protocol protocol = Protocol::tcp);

  explicit SecureSocket(const SocketAddress &address);

  SecureSocket &set_ticket_lifetime(u32 seconds) {
    m_ticket_lifetime_seconds = seconds;
    return *this;
  }

  const var::Data &ticket() const { return m_ticket; }

  SecureSocket &set_ticket(var::View ticket) {
    m_ticket.copy(ticket);
    return *this;
  }

private:
  u32 m_ticket_lifetime_seconds = 60 * 60 * 24UL; // one day

  static void deleter(void * context);
  using SocketPointer = api::UniquePointer<void, decltype(&deleter)>;

  mutable var::Data m_ticket;
  mutable SocketPointer m_context = {nullptr, nullptr};

  int interface_connect(const SocketAddress &address) const final;
  int interface_bind_and_listen(const SocketAddress &address, int backlog)
    const override final;

  int interface_shutdown(const fs::OpenMode how) const final;
  int interface_read(void *buf, int nbyte) const final;
  int interface_write(const void *buf, int nbyte) const final;
};

} // namespace inet

#endif

#endif // SAPI_INET_SECURESOCKET_HPP_
