// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef SAPI_INET_HTTP_HPP_
#define SAPI_INET_HTTP_HPP_

#include <var/Data.hpp>

#include "SecureSocket.hpp"
#include "Socket.hpp"

namespace inet {

class Http : public api::ExecutionContext {
public:
  enum class IsStop { no, yes };

  enum class Status {
    null = 0,
    continue_ = 100,
    switching_protocols = 101,
    processing = 102,
    early_hints = 103,
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,
    multi_status = 207,
    already_reported = 208,
    im_used = 226,
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    switch_proxy = 306,
    temporary_redirect = 307,
    permanent_redirect = 308,
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    misdirected_request = 421,
    unprocessable_entity = 422,
    locked = 423,
    failed_dependency = 424,
    too_early = 425,
    upgrade_required = 426,
    precondition_required = 428,
    too_many_requests = 429,
    request_header_fields_too_large = 431,
    unavailable_for_legal_reasons = 451,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
    variant_also_negotiates = 506,
    insufficient_storage = 507,
    loop_detected = 508,
    not_extended = 510,
    network_authentication_required = 511
  };

  enum class Method {
    null,
    get,
    post,
    put,
    head,
    delete_,
    patch,
    options,
    trace
  };

  struct ExecuteMethod {
    API_PMAZ(
      progress_callback,
      ExecuteMethod,
      const api::ProgressCallback *,
      nullptr);
    API_PMAZ(request, ExecuteMethod, const fs::FileObject *, nullptr);
    API_PMAZ(response, ExecuteMethod, const fs::FileObject *, nullptr);
  };

  using Get = ExecuteMethod;
  using Put = ExecuteMethod;
  using Patch = ExecuteMethod;
  using Post = ExecuteMethod;
  using Remove = ExecuteMethod;

  template <typename FileObjectType> struct MethodResponse {
    FileObjectType file;
    explicit MethodResponse(
      FileObjectType response_value,
      const api::ProgressCallback *progress_callback = nullptr)
      : file{std::move(response_value)}, m_execute_method{
                                           .progress_callback
                                           = progress_callback,
                                           .request = nullptr,
                                           .response = &file} {}
    const ExecuteMethod &get_execute_method() const { return m_execute_method; }

  private:
    ExecuteMethod m_execute_method{};
  };

  template <typename FileObjectType> struct MethodRequest {
    FileObjectType file;
    explicit MethodRequest(
      FileObjectType request_value,
      const api::ProgressCallback *progress_callback = nullptr)
      : file{std::move(request_value)}, m_execute_method{
                                          .progress_callback
                                          = progress_callback,
                                          .request = &file,
                                          .response = nullptr} {}
    const ExecuteMethod &get_execute_method() const { return m_execute_method; }

  private:
    ExecuteMethod m_execute_method{};
  };

  template <typename FileObjectType> struct MethodExchange {
    FileObjectType request;
    FileObjectType response;

    explicit MethodExchange(
      FileObjectType request_value,
      const api::ProgressCallback *progress_callback = nullptr)
      : request{std::move(request_value)}, m_execute_method{
                                             .progress_callback
                                             = progress_callback,
                                             .request = &request,
                                             .response = &response} {}
    const ExecuteMethod &get_execute_method() const { return m_execute_method; }

  private:
    ExecuteMethod m_execute_method{.request = &request, .response = &response};
  };

  static var::KeyString to_string(Status status);
  static var::KeyString to_string(Method method);
  static Method method_from_string(var::StringView string);

  class HeaderField : public var::Pair<var::String> {
  public:
    HeaderField() = default;
    HeaderField(var::StringView key, var::StringView value)
      : var::Pair<var::String>(
        var::String{key}.to_lower(),
        var::String{value}) {}

    static HeaderField from_string(var::StringView string);
    API_NO_DISCARD var::GeneralString to_string() const {
      return key() | ": " | value();
    }
  };

  class Request {
  public:
    Request() = default;
    Request(Method method, var::StringView path, var::StringView version)
      : m_method(method), m_version(version), m_path(path) {}

    explicit Request(var::StringView plain_test) {
      var::StringViewList list = plain_test.split(" \r\n");
      if (list.count() < 3) {
        API_RETURN_ASSIGN_ERROR("", EINVAL);
      }
      m_method = method_from_string(list.at(0));
      m_path = var::String(list.at(1));
      m_version = list.at(2);
    }

    API_NO_DISCARD var::String to_string() const {
      return var::String(Http::to_string(m_method).cstring()) + " " + m_path
             + " " + m_version.cstring();
    }

  private:
    API_RAF(Request, Method, method, Method::null);
    API_RAC(Request, var::KeyString, version);
    API_RAC(Request, var::String, path);
  };

  class Response {
  public:
    Response() = default;
    Response(var::StringView version, Status status)
      : m_status(status), m_version(version) {}
    explicit Response(var::StringView plain_test) {
      var::StringViewList list = plain_test.split(" \r");

      if (list.count() < 2) {
        API_RETURN_ASSIGN_ERROR("", EINVAL);
      }
      m_version = list.at(0);
      m_status
        = static_cast<Status>(var::NumberString(list.at(1)).to_integer());
    }

    API_NO_DISCARD var::GeneralString to_string() const {
      return var::GeneralString(m_version.cstring())
        .append(" ")
        .append(Http::to_string(m_status).cstring());
    }

    API_NO_DISCARD bool is_redirect() const {
      return (static_cast<int>(status()) / 100) == 3;
    }

  private:
    API_RAF(Response, Status, status, Status::null);
    API_RAC(Response, var::KeyString, version);
  };

  explicit Http(var::StringView http_version);
  API_NO_DISCARD const var::String &traffic() const { return m_traffic; }
  API_NO_DISCARD var::String get_header_field(var::StringView key) const;
  API_NO_DISCARD const Response &response() const { return m_response; }
  API_NO_DISCARD const Request &request() const { return m_request; }

  using Send = fs::FileObject::Write;
  using Receive = fs::FileObject::Write;

  API_NO_DISCARD const var::String &header_fields() const {
    return m_header_fields;
  }

protected:
  var::String m_traffic;
  int m_content_length = 0;
  bool m_is_header_dirty = false;

  Request m_request;
  Response m_response;

  virtual Socket &socket() = 0;
  virtual const Socket &socket() const = 0;

  void send(const Response &response) const;
  void send(const Request &request) const;
  var::String receive_header_fields();
  void add_header_field(var::StringView key, var::StringView value);
  void add_header_fields(var::StringView fields);

  void send(const fs::FileObject &file, const Send &options) const;
  void receive(const fs::FileObject &file, const Receive &options) const;

  void set_header_fields(var::StringView a) {
    m_header_fields = var::String(a);
  }

private:
  API_AB(Http, transfer_encoding_chunked, false);
  API_AB(Http, stream_events, false);
  API_AF(Http, var::StringView, http_version, "HTTP/1.1");
  var::String m_header_fields;

  API_AF(Http, size_t, transfer_size, 1024);

  API_NO_DISCARD int get_chunk_size() const;
};

class HttpClient : public Http {
public:
  HttpClient(var::StringView http_version = "HTTP/1.1");

  HttpClient &get(var::StringView path, const Get &options) {
    return execute_method(Method::get, path, options);
  }

  template <typename FileObjectType>
  HttpClient &
  get(var::StringView path, const MethodResponse<FileObjectType> &response) & {
    return execute_method(Method::get, path, response.get_execute_method());
  }
  template <typename FileObjectType>
  HttpClient &&
  get(var::StringView path, const MethodResponse<FileObjectType> &response) && {
    return std::move(get(path, response));
  }
  HttpClient &post(var::StringView path, const Post &options) {
    return execute_method(Method::post, path, options);
  }

  template <typename FileObjectType>
  HttpClient &
  post(var::StringView path, const MethodExchange<FileObjectType> &request) & {
    return execute_method(Method::post, path, request.get_execute_method());
  }
  template <typename FileObjectType>
  HttpClient &&
  post(var::StringView path, const MethodExchange<FileObjectType> &request) && {
    return std::move(post(path, request));
  }

  HttpClient &put(var::StringView path, const Put &options) & {
    return execute_method(Method::put, path, options);
  }

  template <typename FileObjectType>
  HttpClient &
  put(var::StringView path, const MethodRequest<FileObjectType> &request) & {
    return execute_method(Method::put, path, request.get_execute_method());
  }
  template <typename FileObjectType>
  HttpClient &&
  put(var::StringView path, const MethodRequest<FileObjectType> &request) && {
    return std::move(put(path, request));
  }

  template <typename FileObjectType>
  HttpClient &
  put(var::StringView path, const MethodExchange<FileObjectType> &exchange) & {
    return execute_method(Method::put, path, exchange.get_execute_method());
  }
  template <typename FileObjectType>
  HttpClient &&
  put(var::StringView path, const MethodExchange<FileObjectType> &exchange) && {
    return std::move(put(path, exchange));
  }

  HttpClient &patch(var::StringView path, const Patch &options) {
    return execute_method(Method::patch, path, options);
  }

  template <typename FileObjectType>
  HttpClient &patch(
    var::StringView path,
    const MethodExchange<FileObjectType> &exchange) & {
    return execute_method(Method::patch, path, exchange.get_execute_method());
  }

  template <typename FileObjectType>
  HttpClient &&patch(
    var::StringView path,
    const MethodExchange<FileObjectType> &exchange) && {
    return std::move(patch(path, exchange));
  }

  template <typename FileObjectType>
  HttpClient &
  patch(var::StringView path, const MethodRequest<FileObjectType> &request) & {
    return execute_method(Method::patch, path, request.get_execute_method());
  }

  template <typename FileObjectType>
  HttpClient &&
  patch(var::StringView path, const MethodRequest<FileObjectType> &request) && {
    return std::move(patch(path, request));
  }

  // http delete
  HttpClient &remove(var::StringView path, const Remove &options) {
    return execute_method(Method::delete_, path, options);
  }
  template <typename FileObjectType>
  HttpClient &
  remove(var::StringView path, const MethodResponse<FileObjectType> &response) & {
    return execute_method(Method::delete_, path, response.get_execute_method());
  }
  template <typename FileObjectType>
  HttpClient &&
  remove(var::StringView path, const MethodResponse<FileObjectType> &response) && {
    return std::move(remove(path, response));
  }

  /*! \cond */
  HttpClient &options(var::StringView path) {
    return execute_method(Method::options, path, ExecuteMethod());
  }
  HttpClient &trace(var::StringView path) {
    return execute_method(Method::trace, path, ExecuteMethod());
  }

  HttpClient &execute_method(
    Method method,
    var::StringView path,
    const ExecuteMethod &options);

  HttpClient &add_header_field(var::StringView key, var::StringView value) {
    Http::add_header_field(key, value);
    return *this;
  }

  HttpClient &connect(var::StringView domain_name, u16 port = 80) &;
  HttpClient &&connect(var::StringView domain_name, u16 port = 80) && {
    return std::move(connect(domain_name, port));
  }

  virtual Socket &socket() override { return m_socket; }
  virtual const Socket &socket() const override { return m_socket; }

  HttpClient &set_follow_redirects(bool value = true) & {
    m_is_follow_redirects = value;
    return *this;
  }

  HttpClient &&set_follow_redirects(bool value = true) && {
    return std::move(set_follow_redirects(value));
  }

private:
  SocketAddress m_address;
  var::String m_host;
  Socket m_socket;

  API_RAB(HttpClient, connected, false);

  bool m_is_follow_redirects = true;

  virtual void renew_socket() {
    m_socket = Socket(Socket::Family::inet, Socket::Type::stream);
  }
};

#if INET_API_IS_MBEDTLS

class HttpSecureClient : public HttpClient {
public:
  explicit HttpSecureClient(var::StringView http_version = "HTTP/1.1")
    : HttpClient(http_version) {}

  HttpSecureClient &get(var::StringView path, const Get &options) {
    return execute_method(Method::get, path, options);
  }

  template <typename FileObjectType>
  HttpSecureClient &
  get(var::StringView path, const MethodResponse<FileObjectType> &response) & {
    return execute_method(Method::get, path, response.get_execute_method());
  }
  template <typename FileObjectType>
  HttpSecureClient &&
  get(var::StringView path, const MethodResponse<FileObjectType> &response) && {
    return std::move(get(path, response));
  }

  HttpSecureClient &post(var::StringView path, const Post &options) {
    return execute_method(Method::post, path, options);
  }
  template <typename FileObjectType>
  HttpSecureClient &
  post(var::StringView path, const MethodExchange<FileObjectType> &request) & {
    return execute_method(Method::post, path, request.get_execute_method());
  }
  template <typename FileObjectType>
  HttpSecureClient &&
  post(var::StringView path, const MethodExchange<FileObjectType> &request) && {
    return std::move(post(path, request));
  }

  HttpSecureClient &put(var::StringView path, const Put &options) {
    return execute_method(Method::put, path, options);
  }

  template <typename FileObjectType>
  HttpSecureClient &
  put(var::StringView path, const MethodExchange<FileObjectType> &exchange) & {
    return execute_method(Method::put, path, exchange.get_execute_method());
  }
  template <typename FileObjectType>
  HttpSecureClient &&
  put(var::StringView path, const MethodExchange<FileObjectType> &exchange) && {
    return std::move(put(path, exchange));
  }

  HttpSecureClient &patch(var::StringView path, const Patch &options) {
    return execute_method(Method::patch, path, options);
  }

  template <typename FileObjectType>
  HttpSecureClient &patch(
    var::StringView path,
    const MethodExchange<FileObjectType> &exchange) & {
    return execute_method(Method::patch, path, exchange.get_execute_method());
  }

  template <typename FileObjectType>
  HttpSecureClient &&patch(
    var::StringView path,
    const MethodExchange<FileObjectType> &exchange) && {
    return std::move(patch(path, exchange));
  }

  template <typename FileObjectType>
  HttpSecureClient &
  patch(var::StringView path, const MethodRequest<FileObjectType> &request) & {
    return execute_method(Method::patch, path, request.get_execute_method());
  }

  template <typename FileObjectType>
  HttpSecureClient &&
  patch(var::StringView path, const MethodRequest<FileObjectType> &request) && {
    return std::move(patch(path, request));
  }

  // http delete
  HttpSecureClient &remove(var::StringView path, const Remove &options) {
    return execute_method(Method::delete_, path, options);
  }
  template <typename FileObjectType>
  HttpSecureClient &
  remove(var::StringView path, const MethodResponse<FileObjectType> &response) & {
    return execute_method(Method::delete_, path, response.get_execute_method());
  }
  template <typename FileObjectType>
  HttpSecureClient &&
  remove(var::StringView path, const MethodResponse<FileObjectType> &response) && {
    return std::move(remove(path, response));
  }

  HttpSecureClient &options(var::StringView path) {
    return execute_method(Method::options, path, ExecuteMethod());
  }

  HttpSecureClient &trace(var::StringView path) {
    return execute_method(Method::trace, path, ExecuteMethod());
  }

  HttpSecureClient &execute_method(
    Method method,
    var::StringView path,
    const ExecuteMethod &options) {
    HttpClient::execute_method(method, path, options);
    return *this;
  }

  HttpSecureClient &
  add_header_field(var::StringView key, var::StringView value) {
    Http::add_header_field(key, value);
    return *this;
  }

  HttpSecureClient &connect(var::StringView domain_name, u16 port = 443) & {
    HttpClient::connect(domain_name, port);
    return *this;
  }

  HttpSecureClient &&connect(var::StringView domain_name, u16 port = 443) && {
    return std::move(connect(domain_name, port));
  }

  HttpSecureClient &set_follow_redirects(bool value = true) & {
    HttpClient::set_follow_redirects(value);
    return *this;
  }

  HttpSecureClient &&set_follow_redirects(bool value = true) && {
    return std::move(set_follow_redirects(value));
  }

  Socket &socket() override { return m_socket; }
  const Socket &socket() const override { return m_socket; }

private:
  SecureSocket m_socket;

  void renew_socket() final {
    m_socket
      = std::move(SecureSocket(Socket::Family::inet, Socket::Type::stream));
  }
};

#endif

class HttpServer : public Http {
public:
  // socket should already have accepted a new connection
  HttpServer(Socket &&socket, var::StringView http_version = "HTTP/1.1")
    : Http(http_version), m_socket(std::move(socket)) {}

  using Respond = api::Function<IsStop(HttpServer *, const Http::Request &)>;

  [[deprecated("Use run(const Respond &)")]] HttpServer &run(
    void *context,
    IsStop (*respond)(
      HttpServer *server_self,
      void *context,
      const Http::Request &request));

  HttpServer &run(const Respond &respond);

  HttpServer &add_header_field(var::StringView key, var::StringView value) {
    Http::add_header_field(key, value);
    return *this;
  }

  const HttpServer &send(const Response &response) const {
    Http::send(response);
    return *this;
  }

  const HttpServer &
  send(const fs::FileObject &file, const Send &options = Send()) const {
    Http::send(file, options);
    return *this;
  }

  const HttpServer &receive(
    const fs::FileObject &file,
    const Receive &options = Receive()) const {
    Http::receive(file, options);
    return *this;
  }

  HttpServer &
  receive(const fs::FileObject &file, const Receive &options = Receive()) {
    Http::receive(file, options);
    return *this;
  }

  HttpServer &set_transfer_encoding_chunked(bool value = true) {
    Http::set_transfer_encoding_chunked(value);
    return *this;
  }

  Socket &socket() override { return m_socket; }
  const Socket &socket() const override { return m_socket; }

protected:
private:
  API_AB(HttpServer, running, true);
  var::Data m_incoming;
  Socket m_socket;
};

u16 get_pseudorandom_server_port();

} // namespace inet

namespace printer {
Printer &operator<<(Printer &printer, const inet::Http::Request &value);
Printer &operator<<(Printer &printer, const inet::Http::Response &value);
} // namespace printer

#endif // SAPI_INET_HTTP_HPP_
