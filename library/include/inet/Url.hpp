// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef SAPI_INET_URL_HPP_
#define SAPI_INET_URL_HPP_

#include <var/StackString.hpp>

namespace inet {

class Url : public api::ExecutionContext {
public:
  enum class Protocol { null, https, http };

  Url(var::StringView url = "");

  var::String to_string() const;

  u16 port() const { return m_port; }
  Protocol protocol() const { return m_protocol; }
  const var::StringView domain_name() const { return m_domain_name; }
  const var::StringView path() const { return m_path; }

  static var::String encode(var::StringView input);

private:
  var::PathString m_domain_name;
  var::GeneralString m_path;
  Protocol m_protocol;
  u16 m_port;
};

} // namespace inet

#endif // SAPI_INET_URL_HPP_
