#include "../headers/server.h"
#include <asio/io_context.hpp>
#include <cstdint>
#include <iostream>

asio::io_context server_io_context;
class CustomServer : public CSERVER_Server {
public:
  CustomServer(int32_t port, asio::io_context &io_context)
      : CSERVER_Server(port, io_context) {};
  void process_message_overided_by_user(
      network_common_utilites::message_with_conn_obj<
          network_common_utilites::MetaState>
          msg_con) override {
    network_common_utilites::PAYLOAD<network_common_utilites::MetaState> pl =
        network_common_utilites::retrieveOneMessage<
            network_common_utilites::MetaState>(msg_con.res_message);
    auto dc = network_common_utilites::DeserializePayload<
        network_common_utilites::MetaState>(pl, pl.payload_header.ty);
    // Step 5: Print the result
    network_common_utilites::TEST_INT temp =
        std::get<network_common_utilites::TEST_INT>(dc);
    std::cout << temp.t << std::endl;
  }
};
int main() {
  CustomServer s1(5000, server_io_context);
  s1.listen();
  s1.process_messages_on_server();
  server_io_context.run();
  // process the messages
}
