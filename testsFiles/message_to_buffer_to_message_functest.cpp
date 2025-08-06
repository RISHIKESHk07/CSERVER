#include "../headers/common.h"
#include <cstdint>
using namespace network_common_utilites;
int main() {
  custom_logger cl;
  // Step 1: Create message of type CHAT_MESSAGE
  message<MetaState> msg;
  msg.header.id = MetaState::TEST_MESSGAES;
  msg.header.total_size_of_body = 0;

  TEST_INT T;
  T.t = 2;

  // Step 2: Fill ChatMessage struct
  CHAT_MESSAGE chat;
  std::strncpy(chat.sender, "Rishi", sizeof(chat.sender));
  std::strncpy(chat.time, "12:30", sizeof(chat.time));
  std::strncpy(chat.date, "2025-07-19", sizeof(chat.date));
  std::strncpy(chat.group, "CSERVER", sizeof(chat.group));
  // Step 3: Serialize using corrected CreateMessage
  CreateMessage<MetaState, CHAT_MESSAGE>(msg, chat,
                                         PAYLOAD_TYPES::CHAT_MESSAGE);

  CreateMessage<MetaState, TEST_INT>(
      msg, T, network_common_utilites::PAYLOAD_TYPES::TEST_INT);
  std::vector<int8_t> temp_buffer;

  for (const auto &payload : msg.body) {
    // Serialize header
    const auto *header_ptr =
        reinterpret_cast<const int8_t *>(&payload.payload_header);
    temp_buffer.insert(temp_buffer.end(), header_ptr,
                       header_ptr + sizeof(payload.payload_header));

    // Serialize body
    temp_buffer.insert(temp_buffer.end(), payload.payload_body.begin(),
                       payload.payload_body.end());
  }
  cl.log(std::to_string(temp_buffer.size()), 1, 2);
  cl.log(std::to_string(msg.header.total_size_of_body), 1, 2);
  cl.log("---", 1, 2);
  auto restrucr_mesg =
      raw_buffer_to_standar_message_for_reading_body<MetaState>(temp_buffer);

  // Step 4: Verify by retrieving the payload back
  PAYLOAD<MetaState> pl2 = retrieveOneMessage<MetaState>(restrucr_mesg);

  auto dc2 = DeserializePayload<MetaState>(pl2, pl2.payload_header.ty);
  TEST_INT t = std::get<TEST_INT>(dc2);
  std::cout << t.t << std::endl;

  PAYLOAD<MetaState> pl = retrieveOneMessage<MetaState>(restrucr_mesg);

  auto dc = DeserializePayload<MetaState>(pl, pl.payload_header.ty);

  CHAT_MESSAGE deserializedChat = std::get<CHAT_MESSAGE>(dc);

  // Step 5: Print the result

  std::cout << "Sender: " << deserializedChat.sender << std::endl;
  std::cout << "Time: " << deserializedChat.time << std::endl;
  std::cout << "Date: " << deserializedChat.date << std::endl;
  std::cout << "Group: " << deserializedChat.group << std::endl;

  return 0;
}
