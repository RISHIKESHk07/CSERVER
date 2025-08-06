#pragma once
#include "../utils/logger.h"
#include <any>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>
custom_logger cl;
namespace network_common_utilites {

void readFromConnection();
void writeToConnection();

class Server_ConnectionOBJ;
enum class MetaState { TEST_MESSGAES };
enum class PAYLOAD_TYPES : int32_t {
  CHAT_MESSAGE,
  TEST_INT,
  TEST_FLOAT,
  TEST_STRUCT_INT,
  TEST_STRUCT_FLOAT
};
struct CHAT_MESSAGE {
  char sender[100];
  char time[100];
  char date[100];
  char group[100];
};

struct __attribute__((packed)) TEST_INT {
  int t;
};

template <typename T> struct message_header {
  T id;
  int32_t total_size_of_body = 0;
};
template <typename T> struct PAYLOAD_HEADER {
  network_common_utilites::PAYLOAD_TYPES ty;
  int32_t total_size_of_payload = 0;
};
template <typename T> struct PAYLOAD {
  network_common_utilites::PAYLOAD_HEADER<T> payload_header;
  std::vector<int8_t> payload_body;
  ~PAYLOAD() {}
};

template <typename T> struct message {
  network_common_utilites::message_header<T> header;
  std::vector<PAYLOAD<T>> body;
  int number_of_messages = 0;
  ~message() { std::cout << "message delete here" << this << std::endl; }
};

template <typename T, typename DataType>
void CreateMessage(network_common_utilites::message<T> &msg,
                   const DataType &data,
                   network_common_utilites::PAYLOAD_TYPES type) {
  PAYLOAD<T> pl;
  pl.payload_header.ty = type;
  size_t sizeOfData = sizeof(data);
  pl.payload_header.total_size_of_payload = sizeOfData;
  pl.payload_body.resize(sizeOfData);
  std::memcpy(pl.payload_body.data(), &data, sizeof(data));
  msg.body.push_back(std::move(pl));
  msg.header.total_size_of_body += (sizeOfData + sizeof(pl.payload_header));
  msg.number_of_messages += 1;
};
template <typename T>
network_common_utilites::PAYLOAD<T>
retrieveOneMessage(network_common_utilites::message<T> msg) {
  network_common_utilites::PAYLOAD<T> temp = msg.body.back();
  msg.body.pop_back();
  msg.number_of_messages = (-1);
  return temp;
};
// utilites here for deserialization here
template <typename T>
std::shared_ptr<network_common_utilites::message<T>>
raw_buffer_to_standar_message_for_reading_body(
    std::vector<int8_t> &raw_buffer) {
  size_t current_ptr = 0;
  auto result_message = std::make_shared<network_common_utilites::message<T>>();
  cl.log(std::to_string(raw_buffer.size()), 1, 2);
  while (current_ptr < raw_buffer.size()) {
    int sizeofPayloadHeader = sizeof(PAYLOAD_HEADER<T>);
    PAYLOAD_HEADER<T> header;
    PAYLOAD<T> pl;
    std::memcpy(&header, raw_buffer.data() + current_ptr, sizeofPayloadHeader);
    pl.payload_header = std::move(header);
    current_ptr += sizeofPayloadHeader;
    size_t sizeofPayload_body = pl.payload_header.total_size_of_payload;
    switch (pl.payload_header.ty) {
    case network_common_utilites::PAYLOAD_TYPES::CHAT_MESSAGE:
      pl.payload_body.resize(sizeofPayload_body);
      std::memcpy(pl.payload_body.data(), raw_buffer.data() + current_ptr,
                  sizeofPayload_body);
      break;
    case network_common_utilites::PAYLOAD_TYPES::TEST_INT:
      pl.payload_body.resize(sizeofPayload_body);
      std::memcpy(pl.payload_body.data(), raw_buffer.data() + current_ptr,
                  sizeofPayload_body);
      break;
    default:
      break;
    };

    cl.log(std::to_string(current_ptr), 1, 2);
    cl.log(std::to_string(pl.payload_header.total_size_of_payload), 1, 2);
    cl.log(std::to_string(pl.payload_body.size()), 1, 2);

    current_ptr += sizeofPayload_body;
    result_message->body.push_back(pl);
    cl.log(std::to_string(current_ptr), 1, 2);
  }
  return result_message;
}
template <typename T>
network_common_utilites::PAYLOAD<T> retrieveOneMessage(
    std::shared_ptr<network_common_utilites::message<T>> msgPtr) {
  if (!msgPtr || msgPtr->body.empty()) {
    return network_common_utilites::PAYLOAD<T>{};
  }
  network_common_utilites::PAYLOAD<T> temp = msgPtr->body.back();
  msgPtr->body.pop_back();
  msgPtr->number_of_messages -= 1;
  return temp;
}

using payload_types_variant = std::variant<CHAT_MESSAGE, TEST_INT>;
using DeserFunc =
    std::function<payload_types_variant(const std::vector<int8_t> &)>;
std::unordered_map<PAYLOAD_TYPES, DeserFunc> deserializer_map = {
    {PAYLOAD_TYPES::CHAT_MESSAGE,
     [](const std::vector<int8_t> &raw) -> payload_types_variant {
       cl.log("message_chat", 1, 2);
       if (raw.size() != sizeof(CHAT_MESSAGE))
         throw std::runtime_error("Invalid payload size");
       CHAT_MESSAGE obj;
       std::memcpy(&obj, raw.data(), sizeof(CHAT_MESSAGE));
       return obj;
     }},
    {PAYLOAD_TYPES::TEST_INT,
     [](const std::vector<int8_t> &raw) -> payload_types_variant {
       if (raw.size() != sizeof(TEST_INT))
         throw std::runtime_error("Invalid payload size");
       TEST_INT obj;
       std::memcpy(&obj, raw.data(), sizeof(TEST_INT));
       return obj;
     }}
    // Add more types here __ gpt will do that not me
};

template <typename T>
payload_types_variant
DeserializePayload(const network_common_utilites::PAYLOAD<T> &payload,
                   network_common_utilites::PAYLOAD_TYPES expected_type) {
  if (payload.payload_header.ty != expected_type) {
    throw std::runtime_error("Unexpected payload type during deserialization");
  }

  auto s_type = deserializer_map.find(expected_type);
  return (s_type->second(payload.payload_body));
}
template <typename T>
void test_retrieve_MessgaeOne(std::shared_ptr<message<T>> msg) {
  network_common_utilites::PAYLOAD<T> pl = msg->body.back();
  auto dc = network_common_utilites::DeserializePayload<
      network_common_utilites::MetaState>(pl, pl.payload_header.ty);
  // Step 5: Print the result
  network_common_utilites::TEST_INT temp =
      std::get<network_common_utilites::TEST_INT>(dc);

  std::cout << "[TEST]:<--" << temp.t << "-->" << std::endl;
}

template <typename T> struct message_with_conn_obj {
  message_with_conn_obj() = default;
  message_with_conn_obj(const message_with_conn_obj &) = default;

  // Only allow shared_ptr
  message_with_conn_obj(network_common_utilites::message<T>) = delete;
  ~message_with_conn_obj() {
    std::cout << "conn_with_message delete here" << this << std::endl;
  }
  std::shared_ptr<network_common_utilites::message<T>> res_message;
  std::shared_ptr<network_common_utilites::Server_ConnectionOBJ> conn;
};
} // namespace network_common_utilites
