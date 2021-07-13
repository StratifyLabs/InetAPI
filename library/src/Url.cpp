// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include "inet/Url.hpp"
#include "var/Tokenizer.hpp"

using namespace inet;

Url::Url(var::StringView url) {

  if (url.is_empty() == false) {
    size_t position = 0;
    if (url.find("https://" == 0)) {
      m_protocol = Protocol::https;
      position = 8;
    } else if (url.find("http://") == 0) {
      m_protocol = Protocol::http;
      position = 7;
    } else {
      m_protocol = Protocol::null;
      return;
    }

    const size_t path_position = url.find("/", position);
    if (path_position == var::StringView::npos) {
      m_domain_name = url.get_substring_at_position(position);
      return;
    } else {
      m_domain_name = url.get_substring(
        var::StringView::GetSubstring().set_position(position).set_length(
          path_position - position));
    }

    m_path = url.get_substring_at_position(path_position);

  }

  return;
}

var::String Url::to_string() const {
  return var::String("http")
         + (m_protocol == Protocol::https ? var::String("s") : var::String())
         + "://" + m_domain_name + m_path;
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
