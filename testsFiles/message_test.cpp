#include "../headers/common.h" // Assumes this includes everything
#include <iostream>
#include <memory>
// test file for messaging right here ..........
using namespace network_common_utilites;

int main() {
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
  CreateMessage<MetaState, TEST_INT>(msg, T, PAYLOAD_TYPES::TEST_INT);

  // Step 4: Verify by retrieving the payload back
  PAYLOAD<MetaState> pl = retrieveOneMessage<MetaState>(msg);

  auto dc = DeserializePayload<MetaState>(pl, pl.payload_header.ty);

  TEST_INT ty = std::get<TEST_INT>(dc);
  std::cout << ty.t << std::endl;
  // Step 5: Print the result
  CHAT_MESSAGE deserializedChat;
  std::cout << "Sender: " << deserializedChat.sender << std::endl;
  std::cout << "Time: " << deserializedChat.time << std::endl;
  std::cout << "Date: " << deserializedChat.date << std::endl;
  std::cout << "Group: " << deserializedChat.group << std::endl;

  return 0;
}
