// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include "inet/Wifi.hpp"
#include "chrono.hpp"
#include "printer/Printer.hpp"

#if defined __link

int wifi_no_warning = 0;

#else

namespace printer {

Printer &operator<<(Printer &printer, const inet::Wifi::SsidInfo &a) {
  printer.key("name", a.get_name());
  printer.key("channel", var::NumberString(a.channel()));
  printer.key("rssi", var::NumberString(a.rssi()));
  printer.key("security", var::NumberString(static_cast<u8>(a.security())));
  return printer;
}

Printer &operator<<(Printer &printer, const inet::Wifi::IpInfo &a) {
  printer.key("ip", a.get_ip_address().to_string());
  printer.key("dns", a.get_dns_address().to_string());
  printer.key("subnet", a.get_subnet_mask().to_string());
  printer.key("gateway", a.get_gateway_address().to_string());
  return printer;
}

Printer &operator<<(Printer &printer, const inet::Wifi::Info &a) {
  printer.key_bool("valid", a.is_valid());
  printer.key_bool("connected", a.is_connected());
  printer.key("rssi", var::NumberString(a.rssi()));
  printer.open_object("ip");
  printer << a.get_ip_info();
  printer.close_object();
  return printer;
}

} // namespace printer

using namespace inet;

WifiApi Wifi::m_api;

Wifi::Wifi() {
  API_RETURN_IF_ERROR();
  API_SYSTEM_CALL("", initialize());
}

var::Vector<Wifi::SsidInfo> Wifi::scan(const ScanAttributes &attributes,
                                       const chrono::MicroTime &timeout) {
  start_scan(attributes);

  if (is_error()) {
    return var::Vector<SsidInfo>();
  }

  chrono::ClockTimer t;
  t.start();

  while ((t.micro_time() < timeout) && is_scan_busy()) {
    wait(50_milliseconds);
  }

  return get_ssid_info_list();
}

var::Vector<Wifi::SsidInfo> Wifi::get_ssid_info_list() {
  api::ErrorScope error_scope;

  const int count = api()->get_scan_count(m_context);
  if( count < 0 ){
    return SsidInfoList();
  }
  SsidInfoList result;
  result.reserve(count);
  for (int i = 0; i < count; i++) {
    wifi_ssid_info_t info;
    if (api()->get_ssid_info(m_context, i, &info) < 0) {
      return result;
    }

    result.push_back(SsidInfo(info));
  }

  return result;
}

Wifi &Wifi::start_connect(const SsidInfo &ssid_info, const AuthInfo &auth) {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL("",
                  api()->connect(m_context, &ssid_info.info(), &auth.auth()));
  return *this;
}

Wifi::IpInfo Wifi::connect(const SsidInfo &ssid_info, const AuthInfo &auth,
                           const chrono::MicroTime &timeout) {
  API_RETURN_VALUE_IF_ERROR(IpInfo());

  int result = API_SYSTEM_CALL(
      "", api()->connect(m_context, &ssid_info.info(), &auth.auth()));

  if (result < 0) {
    return IpInfo();
  }

  chrono::ClockTimer t;
  t.start();
  Info info;
  do {
    chrono::wait(50_milliseconds);
    info = get_info();
  } while ((t.micro_time() < timeout)
           && (!info.is_connected() || !info.get_ip_info().is_valid()));

  if (info.is_connected() && info.get_ip_info().is_valid()) {
    return info.get_ip_info();
  }

  return IpInfo();
}

#endif
