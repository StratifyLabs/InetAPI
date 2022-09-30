// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include <fs.hpp>
#include <printer/Printer.hpp>
#include <var.hpp>

#include "inet/Http.hpp"
#include "inet/Url.hpp"

#define SHOW_HEADERS 1
#if defined __link
#define AGGREGATE_TRAFFIC(msg) (m_traffic += (msg))
#else
#define AGGREGATE_TRAFFIC(msg)
#endif

namespace printer {
Printer &operator<<(Printer &printer, const inet::Http::Request &value) {
  return printer.key("method", inet::Http::to_string(value.method()))
    .key("path", value.path());
}
Printer &operator<<(Printer &printer, const inet::Http::Response &value) {
  return printer.key("status", inet::Http::to_string(value.status()));
}
} // namespace printer

using namespace inet;
using namespace var;

#define API_HANDLE_STATUS_CASE(c)                                              \
  case Status::c:                                                              \
    result = KeyString().format("%d %s", Status::c, MCU_STRINGIFY(c));         \
    break

KeyString Http::to_string(Status status) {
  KeyString result;
  switch (status) {
    API_HANDLE_STATUS_CASE(null);
    API_HANDLE_STATUS_CASE(continue_);
    API_HANDLE_STATUS_CASE(switching_protocols);
    API_HANDLE_STATUS_CASE(processing);
    API_HANDLE_STATUS_CASE(early_hints);
    API_HANDLE_STATUS_CASE(ok);
    API_HANDLE_STATUS_CASE(created);
    API_HANDLE_STATUS_CASE(accepted);
    API_HANDLE_STATUS_CASE(non_authoritative_information);
    API_HANDLE_STATUS_CASE(no_content);
    API_HANDLE_STATUS_CASE(reset_content);
    API_HANDLE_STATUS_CASE(partial_content);
    API_HANDLE_STATUS_CASE(multi_status);
    API_HANDLE_STATUS_CASE(already_reported);
    API_HANDLE_STATUS_CASE(im_used);
    API_HANDLE_STATUS_CASE(multiple_choices);
    API_HANDLE_STATUS_CASE(moved_permanently);
    API_HANDLE_STATUS_CASE(found);
    API_HANDLE_STATUS_CASE(see_other);
    API_HANDLE_STATUS_CASE(not_modified);
    API_HANDLE_STATUS_CASE(use_proxy);
    API_HANDLE_STATUS_CASE(switch_proxy);
    API_HANDLE_STATUS_CASE(temporary_redirect);
    API_HANDLE_STATUS_CASE(permanent_redirect);
    API_HANDLE_STATUS_CASE(bad_request);
    API_HANDLE_STATUS_CASE(unauthorized);
    API_HANDLE_STATUS_CASE(payment_required);
    API_HANDLE_STATUS_CASE(forbidden);
    API_HANDLE_STATUS_CASE(not_found);
    API_HANDLE_STATUS_CASE(method_not_allowed);
    API_HANDLE_STATUS_CASE(not_acceptable);
    API_HANDLE_STATUS_CASE(proxy_authentication_required);
    API_HANDLE_STATUS_CASE(request_timeout);
    API_HANDLE_STATUS_CASE(conflict);
    API_HANDLE_STATUS_CASE(gone);
    API_HANDLE_STATUS_CASE(length_required);
    API_HANDLE_STATUS_CASE(precondition_failed);
    API_HANDLE_STATUS_CASE(payload_too_large);
    API_HANDLE_STATUS_CASE(uri_too_long);
    API_HANDLE_STATUS_CASE(unsupported_media_type);
    API_HANDLE_STATUS_CASE(range_not_satisfiable);
    API_HANDLE_STATUS_CASE(expectation_failed);
    API_HANDLE_STATUS_CASE(misdirected_request);
    API_HANDLE_STATUS_CASE(unprocessable_entity);
    API_HANDLE_STATUS_CASE(locked);
    API_HANDLE_STATUS_CASE(failed_dependency);
    API_HANDLE_STATUS_CASE(too_early);
    API_HANDLE_STATUS_CASE(upgrade_required);
    API_HANDLE_STATUS_CASE(precondition_required);
    API_HANDLE_STATUS_CASE(too_many_requests);
    API_HANDLE_STATUS_CASE(request_header_fields_too_large);
    API_HANDLE_STATUS_CASE(unavailable_for_legal_reasons);
    API_HANDLE_STATUS_CASE(internal_server_error);
    API_HANDLE_STATUS_CASE(not_implemented);
    API_HANDLE_STATUS_CASE(bad_gateway);
    API_HANDLE_STATUS_CASE(service_unavailable);
    API_HANDLE_STATUS_CASE(gateway_timeout);
    API_HANDLE_STATUS_CASE(http_version_not_supported);
    API_HANDLE_STATUS_CASE(variant_also_negotiates);
    API_HANDLE_STATUS_CASE(insufficient_storage);
    API_HANDLE_STATUS_CASE(loop_detected);
    API_HANDLE_STATUS_CASE(not_extended);
    API_HANDLE_STATUS_CASE(network_authentication_required);
  }

  result(KeyString::Replace().set_old_character('_').set_new_character(' '));

  return result;
}

#define API_HANDLE_METHOD_CASE(c)                                              \
  case Method::c:                                                              \
    result = KeyString(MCU_STRINGIFY(c)).to_upper();                           \
    break

KeyString Http::to_string(Method method) {
  KeyString result;
  switch (method) {
    API_HANDLE_METHOD_CASE(null);
    API_HANDLE_METHOD_CASE(get);
    API_HANDLE_METHOD_CASE(post);
    API_HANDLE_METHOD_CASE(put);
    API_HANDLE_METHOD_CASE(head);
  case Method::delete_:
    return "DELETE";
    API_HANDLE_METHOD_CASE(patch);
    API_HANDLE_METHOD_CASE(options);
    API_HANDLE_METHOD_CASE(trace);
  }

  return result;
}

Http::Method Http::method_from_string(StringView string) {
  const auto input = KeyString(string).to_upper();
  if (input == "GET") {
    return Method::get;
  } else if (input == "POST") {
    return Method::post;
  } else if (input == "PUT") {
    return Method::put;
  } else if (input == "HEAD") {
    return Method::head;
  } else if (input == "DELETE") {
    return Method::delete_;
  } else if (input == "PATCH") {
    return Method::patch;
  } else if (input == "OPTIONS") {
    return Method::options;
  }
  return Method::null;
}

Http::Http(StringView http_version) : m_http_version(http_version) {
  API_ASSERT(http_version.find("HTTP/") == 0);
}

void Http::add_header_field(StringView key, StringView value) {
  if (m_is_header_dirty) {
    m_header_fields.clear();
    m_is_header_dirty = false;
  }

  m_header_fields += key + ": " + value + "\r\n";
}

void Http::add_header_fields(StringView fields) {
  if (m_is_header_dirty) {
    m_header_fields.clear();
    m_is_header_dirty = false;
  }
  m_header_fields += fields;
}

String Http::get_header_field(StringView key) const {
  ViewFile header_view_file(View(header_fields().string_view()));
  GeneralString line;
  while ((line = header_view_file.gets()).is_empty() == false) {
    const auto header_pair = HeaderField::from_string(line);
    if (header_pair.key() == KeyString{key}.to_lower().string_view()) {
      return header_pair.value();
    }
  }

  return {};
}

void Http::send(const Response &response) const {
  socket().write(
    response.to_string() + "\r\n" + header_fields() + "\r\n"
    + (header_fields().is_empty() ? "\r\n" : ""));
}

void Http::send(const fs::FileObject &file, const Send &options) const {
  if (is_transfer_encoding_chunked()) {
    const size_t size = file.size();
    size_t i = 0;
    do {
      const auto page_size
        = options.page_size() > (size - i) ? size - i : options.page_size();

      const auto chunk_message = NumberString().format("%X\r\n", page_size);

      const auto length = chunk_message.length() + page_size + 2;
      char small_buffer[length];

      ViewFile small_write(View(small_buffer, length));

      small_write.write(chunk_message.string_view())
        .write(file, Send(options).set_page_size(page_size).set_size(page_size))
        .write("\r\n");
      socket().write(small_write.seek(0));

      i += page_size;
      API_RETURN_IF_ERROR();
    } while (i < size);
    return;
  }

  socket().write(file, options);
}

void Http::send(const Request &request) const {
#if SHOW_HEADERS
  {
    auto headers = header_fields();
    printf(
      "> %s\n> %s\n",
      request.to_string().cstring(),
      headers.replace(String::Replace{.new_string = "\n> ", .old_string = "\n"})
        .cstring());
  }
#endif
  const auto request_string
    = request.to_string() + "\r\n" + header_fields() + "\r\n";
  socket().write(request_string);
}

int Http::get_chunk_size() const {
  auto line = socket().gets();
  return line.string_view().to_unsigned_long(StringView::Base::hexadecimal);
}

String Http::receive_header_fields() {
  String result;
  GeneralString line;

  result.reserve(512);
  do {
    line = socket().gets('\n');

    AGGREGATE_TRAFFIC(String("> ") + line);
#if SHOW_HEADERS
    printf("< %s", line.cstring());
#endif
    if (line.length() > 2) {
      result += line;
      const auto attribute = HeaderField::from_string(line);

      if (attribute.key() == "content-length") {
        m_content_length
          = static_cast<unsigned int>(attribute.value().to_integer());
      }

      if (attribute.key() == "content-type") {
        // check for event streams
        const auto tokens = attribute.value().split(" ;");
        if (KeyString(tokens.at(0)).to_lower() == "text/event-stream") {
          // accept data until the operation is cancelled
          m_content_length = FSAPI_LINK_DEFAULT_PAGE_SIZE;
        }
      }

      if (
        attribute.key() == "transfer-encoding"
        && (KeyString(attribute.value()).to_lower() == "chunked")) {
        m_is_transfer_encoding_chunked = true;
      }
    }

  } while (line.length() > 2
           && (socket().is_success())); // while reading the header

  m_is_header_dirty = true;
  return result;
}

void Http::receive(const fs::FileObject &file, const Receive &options) const {

  if (is_transfer_encoding_chunked()) {
    // read chunk by chunk
    int chunk_size = 0;
    int bytes_received = 0;
    Array<char, 2> newline;
    do {
      chunk_size = get_chunk_size();
      file.write(
        socket(),
        fs::File::Write(options)
          .set_location(bytes_received)
          .set_page_size(chunk_size)
          .set_size(chunk_size));
      bytes_received += chunk_size;
      // read the \r\n at the end of the data
      socket().read(View(newline));
      API_RETURN_IF_ERROR();
    } while (chunk_size);

    return;
  }

  do {
    // write the bytes to the file
    file.write(socket(), fs::File::Write(options).set_size(m_content_length));
  } while (is_stream_events() && return_value() > 0);
}

HttpClient::HttpClient(StringView http_version) : Http(http_version) {}

HttpClient &HttpClient::execute_method(
  Method method,
  StringView path,
  const ExecuteMethod &options) {

  API_RETURN_VALUE_IF_ERROR(*this);

  if (
    (m_is_connected == false) && (m_host.is_empty() == false)
    && connect(m_host).is_error()) {
    return *this;
  }

  m_content_length = 0;
  int get_file_pos = 0;
  if (options.response) {
    get_file_pos = options.response->location();
  }

  add_header_field("Host", m_host);

  if (get_header_field("accept").is_empty()) {
    add_header_field("Accept", "*/*");
  }

  if (get_header_field("user-agent").is_empty()) {
    add_header_field("User-Agent", "InetAPI");
  }

  if (get_header_field("connection").is_empty()) {
    add_header_field("Connection", "keep-alive");
  }

  if (
    KeyString(get_header_field("accept"))
      .to_lower()
      .string_view()
      .find("text/event-stream")
    == 0) {
    set_stream_events(true);
  } else {
    set_stream_events(false);
  }

  if (options.request) {
    add_header_field(
      "Content-Length",
      NumberString(options.request->size() - options.request->location()));
  }

  m_content_length = 0;
  set_transfer_encoding_chunked(false);

  send(Request(method, path, http_version()));

  if (options.request) {
    send(
      *options.request,
      Send()
        .set_page_size(transfer_size())
        .set_progress_callback(options.progress_callback));
  }

  m_response = Response(socket().gets());
#if SHOW_HEADERS
  printf("< %s\n", m_response.to_string().cstring());
#endif
  set_header_fields(receive_header_fields());

  API_RETURN_VALUE_IF_ERROR(*this);

  const bool is_redirected = m_is_follow_redirects && m_response.is_redirect();

  if (m_content_length || is_transfer_encoding_chunked()) {

    // don't progress on response if request already sent data
    const api::ProgressCallback *callback
      = method == Http::Method::get ? options.progress_callback : nullptr;

    if (options.response && (is_redirected == false)) {
      receive(*options.response, Receive().set_progress_callback(callback));
    } else {
      receive(NullFile(), Receive());
    }
  }

  API_RETURN_VALUE_IF_ERROR(*this);

  if (is_redirected) {

    if (options.response) {
      options.response->seek(get_file_pos, File::Whence::set);
    }

    const auto location = [&](StringView location_field) {
      if (location_field.find("/") != 0) {
        // connect to another server
        Url url(location_field);
        connect(
          url.domain_name(),
          url.protocol() == Url::Protocol::https ? 443 : 80);
        return String{url.path()};
      }
      return String{location_field};
    }(get_header_field("location"));

    if (!location.is_empty()) {
      return execute_method(method, location, options);
    }
  }

  if (KeyString(get_header_field("Connection")).to_upper() == "CLOSE") {
    renew_socket();
    m_is_connected = false;
  }

  return *this;
}

HttpClient &HttpClient::connect(StringView domain_name, u16 port) {
  API_RETURN_VALUE_IF_ERROR(*this);
  AddressInfo address_info(
    AddressInfo::Construct()
      .set_node(domain_name)
      .set_service(
        port != 0xffff ? StringView(NumberString(port)) : StringView(""))
      .set_family(Socket::Family::inet)
      .set_flags(AddressInfo::Flags::canon_name));

  API_RETURN_VALUE_IF_ERROR(*this);
  for (const SocketAddress &address : address_info.list()) {
    renew_socket();
    socket().connect(address);
    if (is_success()) {
      m_is_connected = true;
      m_host = domain_name.to_string();
      return (*this);
    }
    API_RESET_ERROR();
  }

  API_RETURN_VALUE_ASSIGN_ERROR(
    *this,
    GeneralString(domain_name).cstring(),
    ECONNREFUSED);
}

Http::HeaderField Http::HeaderField::from_string(StringView string) {
  const auto colon_pos = string.find(":");
  const auto key
    = KeyString(string.get_substring_with_length(colon_pos)).to_lower();

  auto value = colon_pos != String::npos
                 ? string.get_substring_at_position(colon_pos + 1)
                     .strip_leading_whitespace()
                     .strip_trailing_whitespace()
                 : StringView{};

  return {String{key.string_view()}, String{value}};
}

HttpServer &HttpServer::run(
  void *context,
  IsStop (*respond)(
    HttpServer *server_self,
    void *context,
    const Http::Request &request)) {

  // read socket data

  bool is_stop = false;
  while (is_stop == false) {
    m_request = Request(socket().gets());
    if (m_request.method() != Method::null) {
      if (is_error()) {
        break;
      }

      set_header_fields(receive_header_fields());
      // execute the method
      is_stop = respond && (respond(this, context, m_request) == IsStop::yes);
    }
  }

  return *this;
}

HttpServer &HttpServer::run(const Respond &respond) {
  // read socket data
  auto is_stop = false;
  while (is_stop == false) {
    m_request = Request(socket().gets());
    if (m_request.method() != Method::null) {
      if (is_error()) {
        break;
      }

      set_header_fields(receive_header_fields());
      // execute the method
      is_stop = respond && (respond(this, m_request) == IsStop::yes);
    }
  }
  return *this;
}

u16 inet::get_pseudorandom_server_port() {
  auto result = u16(chrono::ClockTime::get_system_time().nanoseconds() / 1000);
  return (result % (65535 - 49152)) + 49152;
}