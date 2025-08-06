#include "../headers/client.h" // Adjust path if needed
#include "../headers/common.h" // For logging etc.
#include <asio/io_context.hpp>
#include <thread>

using namespace network_common_utilites;

int main() {
  try {
    // Create endpoint for localhost:5000
    asio::io_context client_io;
    asio::ip::tcp::resolver resolver(client_io);
    auto endpoint = resolver.resolve("127.0.0.1", "5000");

    // Create client object
    CSERVER_Client client(endpoint, client_io);

    // Connect to server
    client.connect();

    // Simulate sending a dummy message
    message<MetaState> msg;
    msg.header.id = MetaState::TEST_MESSGAES;
    msg.header.total_size_of_body = 0;

    // Step 2: Fill ChatMessage struct
    TEST_INT temp;
    temp.t = 5;

    CHAT_MESSAGE chat;
    std::strncpy(chat.sender, "Rishi", sizeof(chat.sender));
    std::strncpy(chat.time, "12:30", sizeof(chat.time));
    std::strncpy(chat.date, "2025-07-19", sizeof(chat.date));
    std::strncpy(chat.group, "CSERVER", sizeof(chat.group));
    // Step 3: Serialize using corrected CreateMessage
    // CreateMessage<MetaState, CHAT_MESSAGE>(msg,
    // chat,PAYLOAD_TYPES::CHAT_MESSAGE);

    CreateMessage<MetaState, TEST_INT>(msg, temp, PAYLOAD_TYPES::TEST_INT);
    client.sendMessageToServer(std::move(msg));

    // Let asio run a bit
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Log connection status
    if (client.isConnectedToServer()) {
      std::cout << "Client is connected to server." << std::endl;
    } else {
      std::cout << "Client failed to connect to server." << std::endl;
    }

    client_io.run();
  } catch (const std::exception &e) {
    std::cerr << "Exception in client: " << e.what() << std::endl;
  }

  return 0;
}
