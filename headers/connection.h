#pragma once
#include "../headers/ThreadSafeQ.h"
#include "../headers/common.h"
#include "asio.hpp"
#include <asio/buffer.hpp>
#include <asio/impl/read.hpp>
#include <asio/impl/write.hpp>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>
#include <vector>
namespace network_common_utilites {

template <typename T> struct message_header;

class Server_ConnectionOBJ
    : public std::enable_shared_from_this<Server_ConnectionOBJ> {
private:
  asio::ip::tcp::socket client_socket;
  network_common_utilites::ThreadSafeQ<
      network_common_utilites::message<network_common_utilites::MetaState>>
      OutwardMessageQueue;
  std::shared_ptr<
      network_common_utilites::message<network_common_utilites::MetaState>>
      placeholderBuffer;
  network_common_utilites::ThreadSafeQ<
      network_common_utilites::message_with_conn_obj<MetaState>> &internalQueue;

  void read_header() {
    auto buffer =
        std::make_shared<network_common_utilites::message<MetaState>>();
    asio::async_read(
        client_socket,
        asio::buffer(
            &buffer->header,
            sizeof(network_common_utilites::message_header<MetaState>)),
        [this, buffer](std::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            cl.log("read_header.." +
                       std::to_string(buffer->header.total_size_of_body),
                   1, 2);
            if (buffer->header.total_size_of_body > 0) {
              read_body(buffer);
            } else {
              read_header();
            }
          } else {
            cl.log("read_head_failed ..." + ec.message(), 1, 1);
          }
        });
  };
  void read_body(std::shared_ptr<message<MetaState>> buffer) {
    buffer->body.resize(buffer->header.total_size_of_body);
    cl.log(std::to_string(buffer->body.size()), 1, 2);
    cl.log(std::to_string(int(buffer->header.id)), 1, 2);
    cl.log(std::to_string(buffer->header.total_size_of_body), 1, 2);
    auto temp_raw_bytes_vec = std::make_shared<std::vector<int8_t>>();
    temp_raw_bytes_vec->resize(buffer->header.total_size_of_body);
    asio::async_read(
        client_socket, asio::buffer(*temp_raw_bytes_vec),
        [this, buffer, temp_raw_bytes_vec](std::error_code ec,
                                           std::size_t /*length*/) mutable {
          if (!ec) {
            cl.log("read_body", 1, 1);
            buffer = raw_buffer_to_standar_message_for_reading_body<MetaState>(
                *temp_raw_bytes_vec);
            std::cout << int(buffer->body.back().payload_header.ty)
                      << std::endl;
            test_retrieve_MessgaeOne(buffer);
            network_common_utilites::message_with_conn_obj<MetaState>
                messageTemp;
            messageTemp.res_message = buffer;
            messageTemp.conn = shared_from_this();
            std::cout << "heere" << std::endl;
            test_retrieve_MessgaeOne(buffer);
            try {
              messageTemp.conn = shared_from_this();
            } catch (const std::bad_weak_ptr &e) {
              std::cerr << "[ERROR] shared_from_this() failed: " << e.what()
                        << std::endl;
            }
            cl.log("use_count before push: " +
                       std::to_string(buffer.use_count()),
                   1, 2);
            internalQueue.push_back(std::move(messageTemp));
            // push to server internal queue for processing
            read_header();
          } else {
            cl.log("read_body_failed ..." + ec.message(), 1, 1);
          }
        });
  };
  void write_head() {
    auto message_to_write = (OutwardMessageQueue.front());
    OutwardMessageQueue.pop_front();
    asio::async_write(
        client_socket,
        asio::buffer(&message_to_write, sizeof(message_header<MetaState>)),
        [this, message_to_write](std::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            if (message_to_write.header.total_size_of_body > 0) {
              write_body(message_to_write);
            } else {
              write_head();
            }

          } else {
            cl.log("writing_head_error" + ec.message(), 1, 1);
          }
        });
  };
  void write_body(network_common_utilites::message<MetaState> msg) {
    std::vector<int8_t> temp_buff_binary;
    for (auto &pl : msg.body) {
      const auto *header_ptr =
          reinterpret_cast<const int8_t *>(&pl.payload_header);
      temp_buff_binary.insert(temp_buff_binary.end(), header_ptr,
                              header_ptr + sizeof(pl.payload_header));
      temp_buff_binary.insert(temp_buff_binary.end(), pl.payload_body.begin(),
                              pl.payload_body.end());
    }
    asio::async_write(
        client_socket,
        asio::buffer(temp_buff_binary.data(), msg.header.total_size_of_body),
        [this](std::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            write_head();
          } else {
            cl.log("writing_body_error" + ec.message(), 1, 1);
          };
        });
  };

public:
  Server_ConnectionOBJ(
      asio::ip::tcp::socket s,
      network_common_utilites::ThreadSafeQ<
          network_common_utilites::message_with_conn_obj<MetaState>> &IQ)
      : client_socket(std::move(s)), internalQueue(IQ) {
    cl.log("Connection was made ...", 1, 2);
  };
  void start_listening_from_remote_end() { read_header(); };
  bool isConnected() { return client_socket.is_open(); }
  void sendMessageHelper(network_common_utilites::message<MetaState> &msg) {
    OutwardMessageQueue.push_back(std::move(msg));
    if (!OutwardMessageQueue.empty())
      write_head();
  }

  ~Server_ConnectionOBJ() { cl.log("Connection was destroyed ...", 1, 2); };
};
} // namespace network_common_utilites
