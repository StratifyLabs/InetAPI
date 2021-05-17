#ifndef INETAPI_SNTP_HPP
#define INETAPI_SNTP_HPP

#include <chrono/DateTime.hpp>

namespace inet {

class Sntp : public api::ExecutionContext {
public:
  chrono::DateTime get_time_of_day() const;

private:
  typedef struct MCU_PACK {
    u8 li_vn_mode; // Eight bits. li, vn, and mode.
    // li.   Two bits.   Leap indicator.
    // vn.   Three bits. Version number of the protocol.
    // mode. Three bits. Client will pick mode 3 for client.

    u8 stratum;   // Eight bits. Stratum level of the local clock.
    u8 poll;      // Eight bits. Maximum interval between successive messages.
    u8 precision; // Eight bits. Precision of the local clock.

    u32 rootDelay;      // 32 bits. Total round trip delay time.
    u32 rootDispersion; // 32 bits. Max error aloud from primary clock source.
    u32 refId;          // 32 bits. Reference clock identifier.

    u32 refTm_s; // 32 bits. Reference time-stamp seconds.
    u32 refTm_f; // 32 bits. Reference time-stamp fraction of a second.

    u32 origTm_s; // 32 bits. Originate time-stamp seconds.
    u32 origTm_f; // 32 bits. Originate time-stamp fraction of a second.

    u32 rxTm_s; // 32 bits. Received time-stamp seconds.
    u32 rxTm_f; // 32 bits. Received time-stamp fraction of a second.

    u32 txTm_s; // 32 bits and the most important field the client cares about.
        // Transmit time-stamp seconds.
    u32 txTm_f; // 32 bits. Transmit time-stamp fraction of a second.
  } ntp_packet; // Total: 384 bits or 48 bytes.

  static constexpr auto m_ntp_timestamp_delta =  2208988800ULL;

  API_AF(Sntp, u32, retry_count, 10);
};

}

#endif // INETAPI_SNTP_HPP
