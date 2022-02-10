#include <var.hpp>
#include <printer/Printer.hpp>

#include "inet/Sntp.hpp"
#include "inet/Socket.hpp"

using namespace inet;

chrono::DateTime Sntp::get_time_of_day() const {
  // connect to an SNTP server and get the time of day

  const AddressInfo address_info(inet::AddressInfo::Construct()
                               .set_family(inet::Socket::Family::inet)
                               .set_node("time-c.nist.gov")
                               .set_service("37")
                               .set_type(inet::Socket::Type::stream));

  if(address_info.list().count() == 0 ){
    return chrono::DateTime();
  }

  u32 packet = 0;
  View packet_view(packet);

  for (const auto &address : address_info.list()) {
    Socket socket(address);
    api::ErrorScope error_scope;
    u32 count = 0;
    do {

      reset_error();
      Socket(address)
          .connect(address)
          .write(packet_view)
          .read(packet_view);

    } while ((packet == 0) && (count++ < retry_count()));

    if (count < retry_count()) {
      break;
    }
  }

  if( packet == 0 ){
    return chrono::DateTime();
  }

  packet = ntohl(packet);
  return chrono::DateTime(static_cast<time_t>(packet - m_ntp_timestamp_delta));
}
