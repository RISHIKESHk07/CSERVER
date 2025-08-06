// NOTES:
// README.md
//-------------------------------------------------------------------------
// CSERVER_SERVER
#pragma once
#include "../headers/common.h"
#include "../headers/connection.h"
#include "asio.hpp"
#include <asio/error_code.hpp>
#include <asio/impl/read.hpp>
#include <asio/io_context.hpp>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <sqlite3.h>
#include <sys/types.h>
#include <system_error>
#include <thread>

class CSERVER_Server {
private:
  sqlite3 *db;
  asio::io_context &server_io_context;
  asio::ip::tcp::acceptor server_acceptor_object;
  std::condition_variable server_cv;
  network_common_utilites::ThreadSafeQ<
      std::shared_ptr<network_common_utilites::Server_ConnectionOBJ>>
      ConnectionsQueue;
  network_common_utilites::ThreadSafeQ<
      network_common_utilites::message_with_conn_obj<
          network_common_utilites::MetaState>>
      internalQueue = network_common_utilites::ThreadSafeQ<
          network_common_utilites::message_with_conn_obj<
              network_common_utilites::MetaState>>(&server_cv);
  std::thread server_thread;
  std::vector<std::thread> worker_threads;
  bool stopProcessing = false;
  std::mutex processing_server_mutex;
  void WaitForConnections() {

    server_acceptor_object.async_accept(
        [this](const asio::error_code &error, asio::ip::tcp::socket peer) {
          if (!error) {
            ConnectionsQueue.push_back(
                std::make_shared<network_common_utilites::Server_ConnectionOBJ>(
                    std::move(peer), internalQueue));
            ConnectionsQueue.back()->start_listening_from_remote_end();

            WaitForConnections();

          } else {
            cl.log("Waiting connection error->" + error.message(), 1, 1);
          }
        });
  };

public:
  CSERVER_Server(u_int32_t port, asio::io_context &io_context)
      : server_io_context(io_context),
        server_acceptor_object(
            server_io_context,
            asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {
    std::cout << "Started the server ...." << std::endl;
    // store data to sqlite db directly  ....
    int conn = sqlite3_open("test.db", &db);
    if (conn != SQLITE_OK)
      cl.log("DATABASE NOT OPENING ...", 1, 1);
  };
  ~CSERVER_Server() {
    DisconnectServer();
    sqlite3_close(db);
  };

  void listen() {
    std::cout << "listening ...." << std::endl;
    cl.log("waiting for connections at 5000", 1, 2);
    WaitForConnections();
  };
  void process_messages_on_server() {
    //  make a thread_pool_here for consume these ....
    cl.log("Started the worker for consuming the tasks in the server", 1, 2);
    for (int i = 0; i < 2; i++) {
      worker_threads.emplace_back([this]() {
        while (1) {
          std::unique_lock<std::mutex> lock(processing_server_mutex);
          server_cv.wait(lock, [this]() { return !internalQueue.empty(); });
          auto pm = std::move(internalQueue.front());
          internalQueue.pop_front();
          process_message_overided_by_user(pm);
          cl.log("Task assigned to to thread", 1, 2);
          lock.unlock();
        }
      });
    }
    // call overiding handler here for the ownned messages
  };

  void broadcastMessageToAll(
      network_common_utilites::message<network_common_utilites::MetaState>
          &msg) {
    for (auto &conns : ConnectionsQueue.snapshot()) {
      if (conns->isConnected()) {
        conns->sendMessageHelper(msg);
      }
    }
  };
  void cleanDeadConnections() {
    auto current = ConnectionsQueue.snapshot();

    for (const auto &conn : current) {
      if (conn && !conn->isConnected()) {
        ConnectionsQueue.remove(conn);
      }
    }
  }
  void broadcastMessageToVectorInput();

  virtual void process_message_overided_by_user(
      network_common_utilites::message_with_conn_obj<
          network_common_utilites::MetaState>
          msg_con) = 0;

  void DisconnectClient(
      std::shared_ptr<network_common_utilites::Server_ConnectionOBJ> &obj) {
    auto conn = ConnectionsQueue.find(obj);
    if (conn == ConnectionsQueue.end())
      cl.log("Client not present in the queue", 1, 2);
    else {
      ConnectionsQueue.erase(conn);
      cl.log("Client erased", 1, 2);
    }
  }; // args: disconnect a client in particuolar

  void DisconnectServer() {
    server_io_context.stop();
    for (auto &t : worker_threads) {
      if (t.joinable())
        t.join();
    }
  };
  void NetworkUtilites();
};
