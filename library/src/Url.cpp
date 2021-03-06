// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include "inet/Url.hpp"
#include "var/Tokenizer.hpp"

using namespace inet;

Url::Url(var::StringView url) {

  if (url.is_empty() == false) {

    var::Tokenizer url_tokens
      = var::Tokenizer(url, var::Tokenizer::Construct().set_delimeters("/"));

    // https://domain.name:port/path

    if (url_tokens.count() < 3) {
      return;
    }

    if (var::String(url_tokens.at(0)) == "https:") {
      m_port = 443;
      m_protocol = Protocol::https;
    } else if (var::String(url_tokens.at(0)) == "http:") {
      m_port = 80;
      m_protocol = Protocol::http;
    }

    var::Tokenizer domain_name = var::Tokenizer(
      url_tokens.at(2),
      var::Tokenizer::Construct().set_delimeters(":"));

    if (domain_name.count() > 1) {
      m_port = var::String(domain_name.at(1)).to_integer();
      m_domain_name = var::String(domain_name.at(0));
    } else {
      m_domain_name = var::String(url_tokens.at(2));
    }

    m_path.clear();
    for (u32 i = 3; i < url_tokens.count(); i++) {
      m_path += var::String("/") + url_tokens.at(i);
    }
  }

  return;
}

var::String Url::to_string() const {
  return var::String("http") +
         (m_protocol == Protocol::https ? var::String("s") : var::String()) +
         "://" + m_domain_name + m_path;
}

var::String Url::encode(var::StringView input) {
  var::String result;
  u32 length = input.length();
  for (u32 i = 0; i < length; i++) {
    char c = input.at(i);
    if (
      (c < '0') || ((c > '9') && (c < 'A')) || ((c > 'Z') && (c < 'a'))
      || (c > 'z')) {
      result += var::String().format("%%%X", c);
    } else {
      result += c;
    }
  }
  return result;
}
