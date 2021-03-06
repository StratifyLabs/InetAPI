// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef SAPI_INET_SECURESOCKET_HPP_
#define SAPI_INET_SECURESOCKET_HPP_

#include <mbedtls_api.h>

#include <var/Data.hpp>

#include "api/api.hpp"
#include "chrono/ClockTime.hpp"

#include "Socket.hpp"

namespace inet {

typedef api::Api<mbedtls_api_t, MBEDTLS_API_REQUEST> SecureSocketApi;

class SecureSocket : public Socket {
public:
  SecureSocket();

  explicit SecureSocket(
    Domain domain,
    Type type = Type::stream,
    Protocol protocol = Protocol::tcp);

  explicit SecureSocket(const SocketAddress &address);
  ~SecureSocket();

  SecureSocket(SecureSocket &&a) { std::swap(m_context, a.m_context); }
  SecureSocket &operator=(SecureSocket &&a) {
    std::swap(m_context, a.m_context);
    return *this;
  }

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
  static SecureSocketApi api() { return m_api; }
  static SecureSocketApi m_api;
  u32 m_ticket_lifetime_seconds = 60 * 60 * 24UL; // one day

  mutable var::Data m_ticket;
  mutable void *m_context = nullptr;

  int internal_close() const;

  int interface_connect(const SocketAddress &address) const override final;
  int interface_bind_and_listen(const SocketAddress &address, int backlog)
    const override final;

  int interface_shutdown(const fs::OpenMode how) const final;
  int interface_read(void *buf, int nbyte) const override final;
  int interface_write(const void *buf, int nbyte) const override final;
};

} // namespace inet

#endif // SAPI_INET_SECURESOCKET_HPP_
