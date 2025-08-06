// NOTES:
// README.md
//-------------------------------------------------------------------------
// CSERVER_Client
#pragma once
#include "../headers/common.h"
#include "ThreadSafeQ.h"
#include <asio.hpp>
#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/basic_endpoint.hpp>
#include <deque>
#include <memory>
#include <system_error>
class CSERVER_Client {

private:
  asio::io_context &client_io_context;
  asio::ip::tcp::resolver::results_type &endpoint;
  asio::ip::tcp::socket client_socket_;
  std::thread client_thread;
  network_common_utilites::ThreadSafeQ<std::shared_ptr<
      network_common_utilites::message<network_common_utilites::MetaState>>>
      internalQueue;
  network_common_utilites::ThreadSafeQ<
      network_common_utilites::message<network_common_utilites::MetaState>>
      OutwardMessageQueue;
  std::shared_ptr<
      network_common_utilites::message<network_common_utilites::MetaState>>
      placeholderBuffer;

  void write_header() {
    if (OutwardMessageQueue.empty())
      return;

    asio::async_write(
        client_socket_,
        asio::buffer(&OutwardMessageQueue.front().header,
                     sizeof(OutwardMessageQueue.front().header)),
        [this](std::error_code ec, std::size_t) {
          if (!ec) {
            if (OutwardMessageQueue.front().header.total_size_of_body > 0) {
              placeholderBuffer =
                  std::make_shared<network_common_utilites::message<
                      network_common_utilites::MetaState>>(
                      OutwardMessageQueue.front());
              OutwardMessageQueue.pop_front();
              write_body();
            } else
              write_header(); // Continue with next message
          } else {
            cl.log("Write header error: " + ec.message(), 0, 1);
            client_socket_.close();
          }
        });
  }

  void write_body() {
    cl.log("writing the body.." +
               std::to_string(placeholderBuffer->header.total_size_of_body),
           1, 2);
    std::vector<int8_t> temp_buff_binary;
    for (auto &pl : placeholderBuffer->body) {
      const auto *header_ptr =
          reinterpret_cast<const int8_t *>(&pl.payload_header);
      temp_buff_binary.insert(temp_buff_binary.end(), header_ptr,
                              header_ptr + sizeof(pl.payload_header));
      temp_buff_binary.insert(temp_buff_binary.end(), pl.payload_body.begin(),
                              pl.payload_body.end());
    }
    asio::async_write(
        client_socket_,
        asio::buffer(temp_buff_binary.data(),
                     placeholderBuffer->header.total_size_of_body),
        [this](std::error_code ec, std::size_t) {
          if (!ec) {
            std::cout << int(placeholderBuffer->body[0].payload_header.ty)
                      << std::endl;
            network_common_utilites::test_retrieve_MessgaeOne(
                placeholderBuffer);
            write_header(); // Continue writing next message
          } else {
            cl.log("Write body error: " + ec.message(), 0, 1);
            client_socket_.close();
          }
        });
  }

  void read_header() {
    asio::async_read(client_socket_,
                     asio::buffer(&placeholderBuffer->header,
                                  sizeof(placeholderBuffer->header)),
                     [this](std::error_code ec, std::size_t) {
                       if (!ec) {
                         if (placeholderBuffer->header.total_size_of_body > 0) {
                           placeholderBuffer->body.resize(
                               placeholderBuffer->header.total_size_of_body);
                           read_body();
                         } else {
                           internalQueue.push_back(
                               std::move(placeholderBuffer));
                           read_header(); // Wait for next message
                         }
                       } else {
                         cl.log("Read header error: " + ec.message(), 0, 1);
                         client_socket_.close();
                       }
                     });
  }

  void read_body() {
    auto temp_raw_bytes_vec = std::make_shared<std::vector<int8_t>>();
    temp_raw_bytes_vec->resize(placeholderBuffer->header.total_size_of_body);
    asio::async_read(
        client_socket_, asio::buffer(*temp_raw_bytes_vec),
        [this, temp_raw_bytes_vec](std::error_code ec, std::size_t) mutable {
          if (!ec) {
            auto buffer = network_common_utilites::
                raw_buffer_to_standar_message_for_reading_body<
                    network_common_utilites::MetaState>(*temp_raw_bytes_vec);
            internalQueue.push_back(std::move(buffer));
            read_header();
          } else {
            cl.log("Read body error: " + ec.message(), 0, 1);
            client_socket_.close();
          }
        });
  }

public:
  CSERVER_Client(asio::ip::tcp::resolver::results_type &endpoints,
                 asio::io_context &io)
      : client_io_context(io), client_socket_(client_io_context),
        endpoint(endpoints) {};
  virtual ~CSERVER_Client() { disconnect(); };
  void disconnect() {}
  void connect() {
    asio::async_connect(
        client_socket_, endpoint,
        [this](std::error_code ec,
               asio::ip::basic_endpoint<asio::ip::tcp> /*peer_endpoint*/) {
          if (!ec) {
            read_header();
          } else {
            cl.log("Error connecting client side " + ec.message(), 0, 1);
          }
        });
  };
  bool isConnectedToServer() { return client_socket_.is_open(); };
  void process_message();
  void sendMessageToServer(
      network_common_utilites::message<network_common_utilites::MetaState>
          message) {
    asio::post(client_io_context, [this, message]() mutable {
      OutwardMessageQueue.push_back(std::move(message));
      if (!OutwardMessageQueue.empty())
        write_header();
    });
  };
};
