// Copyright 2016-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef INET_API_INET_WIFI_HPP
#define INET_API_INET_WIFI_HPP

#include <sdk/api.h>

#if defined SDK_API_WIFI_API_T || defined SOS_API_WIFI_API_H

#include <chrono/ClockTimer.hpp>
#include <chrono/DateTime.hpp>

#include "IpAddress.hpp"

namespace inet {

typedef api::Api<wifi_api_t, WIFI_API_REQUEST> WifiApi;

class Wifi : public api::ExecutionContext, public WifiApi {
public:
  enum class Security {
    invalid = WIFI_SECURITY_INVALID,
    open = WIFI_SECURITY_OPEN,
    wep = WIFI_SECURITY_WEP,
    wpa_psk = WIFI_SECURITY_WPA_PSK,
    x802_1x = WIFI_SECURITY_802_1X
  };

  static const char *to_cstring(Security value) {
    switch (value) {
    case Security::invalid:
      return "invalid";
    case Security::open:
      return "open";
    case Security::wep:
      return "wep";
    case Security::wpa_psk:
      return "wpa_psk";
    case Security::x802_1x:
      return "x802_1x";
    }
    return "unknown";
  }

  static Security security_from_string(const var::StringView name) {

    if (name == "invalid") {
      return Security::invalid;
    }

    if (name == "open") {
      return Security::open;
    }

    if (name == "wep") {
      return Security::wep;
    }

    if (name == "wpa_psk") {
      return Security::wpa_psk;
    }

    if (name == "x802_1x") {
      return Security::x802_1x;
    }

    return Security::invalid;
  }

  enum class ScanRegion {
    north_america = WIFI_SCAN_REGION_NORTH_AMERICA,
    asia = WIFI_SCAN_REGION_ASIA
  };

  class SsidInfo {
  public:
    SsidInfo() { m_info = {}; }
    explicit SsidInfo(const wifi_ssid_info_t &info) : m_info(info) {}

    bool is_valid() const { return m_info.ssid[0] != 0; }

    var::StringView get_name() const { return m_info.ssid; }
    const char * get_name_cstring() const { return m_info.ssid; }

    SsidInfo &set_name(const var::StringView value) {
      var::View(m_info.ssid).fill(0).pop_back().copy(var::View(value));
      return *this;
    }

    Security security() const { return Security(m_info.security); }

    SsidInfo &set_security(Security value) {
      m_info.security = static_cast<u8>(value);
      return *this;
    }

    API_ACCESS_MEMBER_FUNDAMENTAL(SsidInfo, u8, info, channel)
    API_ACCESS_MEMBER_FUNDAMENTAL(SsidInfo, s8, info, rssi)

    const wifi_ssid_info_t &info() const { return m_info; }

    bool operator==(const SsidInfo &a) const {
      return a.get_name() == get_name();
    }

  private:
    wifi_ssid_info_t m_info;
  };

  class AuthInfo {
  public:
    AuthInfo() { m_auth = {}; }

    explicit AuthInfo(const wifi_auth_info_t &auth) : m_auth(auth) {}

    explicit AuthInfo(const var::StringView passphrase) {
      m_auth = {0};
      var::View(m_auth.password).copy(var::View(passphrase));
    }

    var::GeneralString get_passphrase() const {
      var::GeneralString result;
      var::View(result.data(), result.capacity())
          .fill(0)
          .copy(var::View(m_auth.password));
      return result;
    }

    const wifi_auth_info_t &auth() const { return m_auth; }

  private:
    wifi_auth_info_t m_auth;
  };

  class ScanAttributes {
  public:
    ScanAttributes() { m_attributes = {}; }

    static ScanAttributes get_default() {
      return ScanAttributes()
          .set_region(ScanRegion::north_america)
          .set_passive(false)
          .set_channel(0xff)
          .set_slot_count(5)
          .set_slot_time(100_milliseconds)
          .set_probe_count(2)
          .set_rssi_threshold(-90);
    }

    explicit ScanAttributes(const wifi_scan_attributes_t &attributes)
        : m_attributes(attributes) {}

    bool is_valid() const { return m_attributes.slot_count != 0; }

    ScanAttributes &set_passive(bool value = true) {
      m_attributes.is_passive = value;
      return *this;
    }

    ScanAttributes &set_slot_time(const chrono::MicroTime &value) {
      m_attributes.slot_time_ms = value.milliseconds();
      return *this;
    }

    ScanAttributes &set_region(ScanRegion value) {
      m_attributes.scan_region = static_cast<u8>(value);
      return *this;
    }

    chrono::MicroTime slot_time() const {
      return chrono::MicroTime(m_attributes.slot_time_ms * 1000UL);
    }

    API_ACCESS_MEMBER_FUNDAMENTAL(ScanAttributes, u8, attributes, channel)
    API_ACCESS_MEMBER_FUNDAMENTAL(ScanAttributes, u8, attributes, slot_count)
    API_ACCESS_MEMBER_FUNDAMENTAL(ScanAttributes, u8, attributes, probe_count)
    API_ACCESS_MEMBER_FUNDAMENTAL(ScanAttributes, u8, attributes,
                                  rssi_threshold)
    API_READ_ACCESS_MEMBER_FUNDAMENTAL(ScanAttributes, u8, attributes,
                                       scan_region)

    bool is_passive() const { return m_attributes.is_passive; }

    const wifi_scan_attributes_t &attributes() const { return m_attributes; }

  private:
    wifi_scan_attributes_t m_attributes;
  };

  class IpInfo {
  public:
    IpInfo() { m_info = {}; }
    explicit IpInfo(const wifi_ip_info_t &info) : m_info(info) {}

    bool is_valid() const { return m_info.ip_address != 0; }

    IpInfo &set_lease_time(const chrono::MicroTime &value) {
      m_info.lease_time_s = value.seconds();
      return *this;
    }

    chrono::MicroTime lease_time() const {
      return chrono::MicroTime(m_info.lease_time_s * 1_seconds);
    }

    API_ACCESS_MEMBER_FUNDAMENTAL(IpInfo, u32, info, ip_address)
    API_ACCESS_MEMBER_FUNDAMENTAL(IpInfo, u32, info, dns_address)
    API_ACCESS_MEMBER_FUNDAMENTAL(IpInfo, u32, info, subnet_mask)
    API_ACCESS_MEMBER_FUNDAMENTAL(IpInfo, u32, info, gateway_address)

    IpAddress4 get_ip_address() const { return IpAddress4(ip_address()); }

    IpAddress4 get_dns_address() const { return IpAddress4(dns_address()); }

    IpAddress4 get_gateway_address() const {
      return IpAddress4(gateway_address());
    }

    IpAddress4 get_subnet_mask() const { return IpAddress4(subnet_mask()); }

  private:
    wifi_ip_info_t m_info;
  };

  class Info {
  public:
    Info() { m_info = {}; }
    Info(const wifi_info_t &info) { m_info = info; }

    bool is_valid() const { return m_info.resd0 == WIFI_API_INFO_RESD; }

    var::StringView ssid() const { return m_info.ssid; }

    IpInfo get_ip_info() const { return IpInfo(m_info.ip); }

    API_ACCESS_MEMBER_FUNDAMENTAL(Info, u8, info, security)
    API_ACCESS_MEMBER_FUNDAMENTAL(Info, u8, info, rssi)

    bool is_connected() const { return m_info.is_connected; }

    const wifi_info_t &info() const { return m_info; }

  private:
    wifi_info_t m_info;
  };

  Wifi();
  ~Wifi() { finalize(); }

  Wifi &start_connect(const SsidInfo &ssid_info, const AuthInfo &auth);

  IpInfo connect(const SsidInfo &ssid_info, const AuthInfo &auth,
                 const chrono::MicroTime &timeout = 10_seconds);

  Wifi &disconnect() {
    API_RETURN_VALUE_IF_ERROR(*this);
    API_SYSTEM_CALL("", api()->disconnect(m_context));
    return *this;
  }

  using SsidInfoList = var::Vector<SsidInfo>;

  SsidInfoList
  scan(const ScanAttributes &attributes = ScanAttributes::get_default(),
       const chrono::MicroTime &timeout = 20_seconds);

  Wifi &start_scan(const ScanAttributes &attributes) {
    API_RETURN_VALUE_IF_ERROR(*this);
    API_SYSTEM_CALL("", api()->start_scan(m_context, &attributes.attributes()));
    return *this;
  }

  bool is_scan_busy() const {
    API_RETURN_VALUE_IF_ERROR(false);
    API_ASSERT(m_context != nullptr);
    api::ErrorScope error_scope;
    int result = api()->get_scan_count(m_context);
    return result < 0;
  }

  Info get_info() const {
    API_RETURN_VALUE_IF_ERROR(Info());
    API_ASSERT(m_context != nullptr);
    wifi_info_t info;
    if (api()->get_info(m_context, &info) < 0) {
      return Info();
    }
    return Info(info);
  }

  SsidInfoList get_ssid_info_list();

  Wifi &set_mode();
  Wifi &set_mac_address(u8 mac_address[6]);
  const Wifi &get_mac_address(u8 mac_address[6]);
  const Wifi &get_factory_mac_address(u8 mac_address[6]);
  Wifi &set_ip_address(const wifi_ip_info_t *static_ip_address);

  Wifi &set_sleep_mode(void *context);
  Wifi &sleep(void *context, u32 sleep_time_ms);
  Wifi &set_device_name(void *context, const char *name);
  Wifi &set_tx_power(void *context, u8 power_level);

  static WifiApi &api() { return m_api; }

private:
  static WifiApi m_api;
  void *m_context = nullptr;

  int initialize() {
    if (api().is_valid() == false) {
      return -1;
    }
    return api()->init(&m_context);
  }

  void finalize() { api()->deinit(&m_context); }
};

} // namespace inet

namespace printer {
class Printer;
Printer &operator<<(Printer &printer, const inet::Wifi::SsidInfo &a);
Printer &operator<<(Printer &printer, const inet::Wifi::Info &a);
Printer &operator<<(Printer &printer, const inet::Wifi::IpInfo &a);
} // namespace printer

#endif

#endif // INET_API_INET_WIFI_HPP
