#include "boost/asio.hpp"
#include "utilites.h"
#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/completion_condition.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/detail/string_view.hpp>
#include <boost/asio/impl/read.hpp>
#include <boost/asio/impl/read_until.hpp>
#include <boost/asio/impl/write.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/date_time/time_defs.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <ios>
#include <istream>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>

class ClientBase {

protected:
  class Connection;

public:
  class headermatch {
    int crlf = 0;
    int lflf = 0;

  public:
    std::pair<boost::asio::buffers_iterator<boost::asio::const_buffer>, bool>
    operator()(boost::asio::buffers_iterator<boost::asio::const_buffer> begin,
               boost::asio::buffers_iterator<boost::asio::const_buffer> end) {
      auto it = begin;
      for (; it != end; ++it) {
        if (*it == '\n') {
          if (crlf == 1)
            ++crlf;
          else if (crlf == 2)
            crlf = 0;
          else if (crlf == 3)
            return {++it, true};
          if (lflf == 0)
            ++lflf;
          else if (lflf == 1)
            return {++it, true};
        } else if (*it == '\r') {
          if (crlf == 0)
            ++crlf;
          else if (crlf == 2)
            ++crlf;
          else
            crlf = 0;
          lflf = 0;

        } else {
          crlf = 0;
          lflf = 0;
        }
      }
      return {it, false};
    }
  };
  class Content : public std::istream {
    friend class ClientBase;

  public:
    bool end;
    std::size_t size_of_content() { return buffer.size(); }
    std::string content_string() {
      return std::string(boost::asio::buffers_begin(buffer.data()),
                         boost::asio::buffers_end(buffer.data()));
    }

  private:
    boost::asio::streambuf &buffer;
    Content(boost::asio::streambuf &streambuf)
        : std::istream(&streambuf), buffer(streambuf) {};
  }; // will use this connection & session & response classes
  //
  class Response {
    friend class ClientBase;
    friend class Connection;
    class Shared {
    public:
      std::string http_version;
      std::string status_code;
    };

  public:
    Utilites::CaseInsenstiveMultimap header;
    Content content;
    std::shared_ptr<Shared> shared_ptr;
    std::string http_version;
    std::string status_code;

    Response(std::size_t max_response_streambuf_size,
             const std::shared_ptr<Connection> &connection_) noexcept
        : responseBuffer(max_response_streambuf_size),
          shared_ptr(std::make_shared<Shared>()), response_conn(connection_),
          content(responseBuffer), http_version(shared_ptr->http_version),
          status_code(shared_ptr->status_code) {};
    Response(const Response &response)
        : responseBuffer(response.responseBuffer.max_size()),
          shared_ptr(response.shared_ptr),
          response_conn(response.response_conn), content(responseBuffer),
          http_version(response.shared_ptr->http_version),
          status_code(response.shared_ptr->status_code) {}

  private:
    boost::asio::streambuf responseBuffer;
    std::weak_ptr<Connection> response_conn;
  };

  class Config {
    friend class ClientBase;

  private:
    Config() noexcept {}

  public:
    long timeout = 0;
    long timeout_connect = 0;
    std::size_t max_response_streambuf_size =
        (std::numeric_limits<std::size_t>::max)();
    std::string proxy_server; //(server:port) format
  };

protected:
  class Connection : public std::enable_shared_from_this<Connection> {
  public:
    template <typename... Args>
    Connection(std::shared_ptr<Utilites::scope_runner> handler_runner_,
               Args &&...args) noexcept
        : scopped_runner(std::move(handler_runner_)),
          socket(
              new boost::asio::ip::tcp::socket(std::forward<Args>(args)...)) {}
    std::shared_ptr<Utilites::scope_runner>
        scopped_runner; // handle runner here
    std::unique_ptr<boost::asio::ip::tcp::socket> socket;
    bool in_use = false;
    bool attemp_reconnect = false;
    std::unique_ptr<boost::asio::steady_timer> timer;
    void close() noexcept {
      boost::system::error_code ec;
      socket->lowest_layer().shutdown(
          boost::asio::ip::tcp::socket::shutdown_both, ec);
      socket->lowest_layer().cancel(ec);
    }
    void set_timeout(long seconds) {
      if (seconds == 0) {
        timer = nullptr;
        return;
      }
      timer = std::unique_ptr<boost::asio::steady_timer>(
          new boost::asio::steady_timer(socket->get_executor(),
                                        std::chrono::seconds(seconds)));
      std::weak_ptr<Connection> conn_weak(this->shared_from_this());
      timer->async_wait([conn_weak](const boost::system::error_code &ec) {
        if (auto c = conn_weak.lock()) {
          c->close();
        }
      });
    };
    void cancel_timeout() {
      if (timer) {
        try {
          timer->cancel();
        } catch (...) {
        }
      }
    }
  };
  class Session {
  public:
    Session(std::size_t max_response_streambuf_size,
            std::shared_ptr<Connection> connection_,
            std::unique_ptr<boost::asio::streambuf> request_streambuf_) noexcept
        : session_conn(std::move(connection_)),
          request_buffer(std::move(request_streambuf_)),
          response(new Response(max_response_streambuf_size, session_conn)) {}

    std::shared_ptr<Connection> session_conn;
    std::unique_ptr<boost::asio::streambuf> request_buffer;
    std::shared_ptr<Response> response;
    std::function<void(const boost::system::error_code &)> callback;
  };

public:
  Config config;
  std::string host;
  unsigned int port;
  std::list<std::shared_ptr<Connection>> connections_pool;
  std::mutex connection_pool_mutex;
  std::shared_ptr<Utilites::scope_runner> scopped_runner;
  std::shared_ptr<boost::asio::io_context> io_service;
  void request(const std::string &method, std::string &path,
               std::istream &content,
               const Utilites::CaseInsenstiveMultimap &header,
               std::function<void(std::shared_ptr<Response>,
                                  const boost::system::error_code &)>
                   &&request_callback_) {
    auto session = std::make_shared<Session>(
        config.max_response_streambuf_size, get_connection(),
        create_header_message_buffer(method, path, header));
    auto weak_session = std::weak_ptr<Session>(session);
    auto request_callback = std::function<void(
        std::shared_ptr<Response>, const boost::system::error_code &)>(
        std::move(request_callback_));
    // callback handler after the request is processed situation
    session->callback = [this, request_callback,
                         weak_session](const boost::system::error_code &ec) {
      // checking the session object not killed before work done
      if (auto session = weak_session.lock()) {
        if (session->response->content.end == true) {
          session->session_conn->in_use = false;
          session->session_conn->attemp_reconnect = false;
        } // check if in current iteration we are in the end of content ...

        {
          std::lock_guard<std::mutex> lock(connection_pool_mutex);
          int unUsedConns = 0;
          for (auto it = this->connections_pool.begin();
               it != this->connections_pool.end();) {

            if (*it == session->session_conn) {
              it = this->connections_pool.erase(it);
            } else {
              if ((*it)->in_use == false)
                unUsedConns++;
              if (unUsedConns > 1) {
                it = this->connections_pool.erase(it);
              } else {
                it++;
              }
            }
          }
        }
        if (request_callback) {
          request_callback(session->response, ec);
        }
      }
    };
    // add the content & tranfer encoding headers here
    content.seekg(0, std::ios::end);
    auto content_length = content.tellg();
    content.seekg(0, std::ios::beg);
    std::ostream write_buffer(session->request_buffer.get());
    if (content_length > 0) {
      auto head_it = header.find("Content-Length");
      if (head_it == header.end()) {
        auto head_et_it = header.find("Transfer-Encoding");
        if (head_et_it == header.end() || head_et_it->second != "chunked")
          write_buffer << "Content-Length: " << content_length << "\r\n";
      }
    }

    write_buffer << "\r\n";
    write_buffer << content.rdbuf();

    connect(session);
  };
  std::unique_ptr<boost::asio::streambuf>
  create_header_message_buffer(const std::string &method, std::string &path,
                               const Utilites::CaseInsenstiveMultimap &header) {
    auto path_c = path;
    if (path_c == "")
      path_c = "/";
    path = "http://" + host + ":" + std::to_string(port) + path_c;

    std::unique_ptr<boost::asio::streambuf> streambuf(
        new boost::asio::streambuf());
    std::ostream write_buf(streambuf.get());
    write_buf << method << " " << path << " " << "HTTP/1.1\r\n";
    write_buf << "Host: " << host;
    write_buf << "Port: " << port;
    write_buf << "\r\n";
    for (auto h : header) {
      write_buf << h.first << ": " << h.second;
    }
    return streambuf;
  }
  std::shared_ptr<Connection> get_connection() {
    std::lock_guard<std::mutex> lock(connection_pool_mutex);
    for (auto &c : connections_pool) {
      if (c->in_use == false) {
        connection_pool_mutex.unlock();
        return c;
      }
    }
    auto new_conn = std::make_shared<Connection>(scopped_runner, *io_service);
    new_conn->in_use = true;
    new_conn->attemp_reconnect = true;
    connections_pool.emplace_back(new_conn);
    connection_pool_mutex.unlock();
    return new_conn;
  };

  // write
  void write(const std::shared_ptr<Session> &session) {
    boost::asio::async_write(
        *session->session_conn->socket, session->request_buffer->data(),
        [this, session](const boost::system::error_code &ec,
                        std::size_t /*bytes_transferred */) {
          auto l = scopped_runner->continue_lock(); // stop the process from
                                                    // moving forward at all
          if (!l)
            return;
          if (!ec) {
            this->read(session);
          } else {
            session->callback(ec);
          }
        });
  }
  void read(const std::shared_ptr<Session> &session) {
    // read the header & parse the response message and check for errors
    //  read content
    //  read sse
    //  read Transfer-Encoding
    //
    boost::asio::async_read_until(
        *session->session_conn->socket, session->response->responseBuffer,
        "\r\n\r\n",
        [this, session](const boost::system::error_code &ec,
                        std::size_t bytes_transferred) {
          auto l = session->session_conn->scopped_runner->continue_lock();
          if (!l)
            return;
          if (!ec) {
            size_t num_additional =
                session->response->responseBuffer.size() - bytes_transferred;
            if (!Utilites::ResponseMessage::parse(
                    session->response->content, session->response->http_version,
                    session->response->status_code,
                    session->response->header)) {
              session->callback(ec); // parse error here
              return;
            }
            auto head_it = session->response->header.find("Content-Length");
            if (head_it != session->response->header.end()) {
              auto size = std::stoul(head_it->second);
              if (num_additional < size) {
                // read->content(session,size-num_additonal);
              } else
                session->callback(ec);
            } else if ((head_it = session->response->header.find(
                            "Transfer-Encoding")) !=
                           session->response->header.end() &&
                       head_it->second == "chunked") {
              auto chunked_sink = std::make_shared<boost::asio::streambuf>(
                  std::max<std::size_t>(
                      16 + 2, session->response->responseBuffer.size()));
              auto &source = session->response->responseBuffer;
              auto &target = *chunked_sink;
              target.commit(boost::asio::buffer_copy(
                  target.prepare(source.size()),
                  source.data()));           // data preped for read
              source.consume(source.size()); // cleaning up the buffer
              //
              this->read_chunked(session, chunked_sink);

            } else if ((head_it =
                            session->response->header.find("Content-Type")) !=
                           session->response->header.end() &&
                       head_it->second == "text/event-stream") {
              auto event_sink = std::make_shared<boost::asio::streambuf>(
                  this->config.max_response_streambuf_size);
              auto &source = session->response->responseBuffer;
              auto &target = *event_sink;
              target.commit(boost::asio::buffer_copy(
                  target.prepare(source.size()),
                  source.data()));           // data preped for read
              source.consume(source.size()); // cleaning up the buffer
                                             //
              session->callback(ec);

              // read->sse_event();

            } else
              session->callback(ec);
          } else {
            session->callback(ec);
          }
        });
  };
  // read mechanism for various types
  void read_content(std::shared_ptr<Session> &session, size_t size) {
    boost::asio::async_read(
        *session->session_conn->socket, session->response->responseBuffer,
        [&session, this, size](const boost::system::error_code &ec,
                               size_t bytes_transferred) {
          if (!ec) {
            if (session->response->responseBuffer.size() ==
                    session->response->responseBuffer.max_size() &&
                size > bytes_transferred) {
              session->response->content.end = false;
              session->response =
                  std::make_shared<Response>(*session->response);
              this->read_content(session, size - bytes_transferred);
            } else {
              session->callback(ec);
            }
          } else {
            std::cout << "Read content ..." + ec.message() << std::endl;
          }
        });
  };
  void
  read_chunked(const std::shared_ptr<Session> &session,
               const std::shared_ptr<boost::asio::streambuf> &streambuffer) {
    // read until you find first chunk end from the streambuffer , read the
    // content-length , calc num_add , check if content-length < num_additonal
    // -> directly psuh into buffer check if content-length > num_additonal -->
    // need make read additional call size content-length - num_additional check
    // if content-length + 2 > num_additional --> missing crlf , so call a
    // single or double read to complete this process next call read_next func
    // --> call the transfer_chunk if next size not zero or end the process and
    // move to the write process
    boost::asio::async_read_until(
        *session->session_conn->socket, *streambuffer, "\r\n",
        [this, session, streambuffer](const boost::system::error_code &ec,
                                      size_t bytes_transferred) {
          auto l = session->session_conn->scopped_runner->continue_lock();
          if (!l)
            return;
          if (!ec) {
            std::istream stream(streambuffer.get());
            std::string line;
            std::getline(stream, line);
            bytes_transferred -= line.size() + 1;
            size_t cl;
            cl = std::stoul(line, 0, 16);

            if (cl == 0) { // terminate this here
              session->callback(boost::system::error_code());
            }
            size_t num_additinal = streambuffer->size() - bytes_transferred;
            auto bytes_moved = std::min<size_t>(num_additinal, cl);
            if (bytes_moved > 0) {
              auto &source = *streambuffer;
              auto &target = session->response->responseBuffer;
              target.commit(boost::asio::buffer_copy(
                  target.prepare(bytes_moved),
                  source.data()));         // data preped for read
              source.consume(bytes_moved); // cleaning up the buffer
            }
            if (cl > num_additinal) {
              boost::asio::async_read(
                  *session->session_conn->socket,
                  session->response->responseBuffer,
                  boost::asio::transfer_exactly(cl - num_additinal),
                  [session, streambuffer,
                   this](const boost::system::error_code &ec,
                         size_t bytes_transferred) {
                    if (!ec) {
                      boost::asio::streambuf nullbug =
                          boost::asio::streambuf(2);
                      boost::asio::async_read(
                          *session->session_conn->socket, nullbug,
                          boost::asio::transfer_exactly(2),
                          [this, session,
                           streambuffer](const boost::system::error_code &ec,
                                         size_t bytes_transferred) {
                            if (!ec) {
                              this->read_chunked(session, streambuffer);
                            } else {
                              session->callback(ec);
                            }
                          });
                    } else {
                      session->callback(ec);
                    }
                  });
            } else if (cl + 2 > num_additinal) {

              if (cl + 2 - num_additinal == 1)
                stream.get(); // if one of the bytes is in buffer/stream already
                              // we fetch it
              boost::asio::streambuf nullbuff = boost::asio::streambuf(2);
              boost::asio::async_read(
                  *session->session_conn->socket, nullbuff,
                  boost::asio::transfer_exactly(cl + 2 - num_additinal),
                  [this, session,
                   streambuffer](const boost::system::error_code &ec,
                                 size_t bytes_transferred) {
                    if (!ec) {
                      this->read_chunked(session, streambuffer);
                    } else {
                      session->callback(ec);
                    }
                  });

            } else {
              stream.get();
              stream.get();
              this->read_chunked(session, streambuffer);
            }

          } else {
            session->callback(ec);
          }
        });
  }
  ClientBase(std::string host, unsigned int port) : host(host), port(port) {};
  // connect
  void connect(const std::shared_ptr<Session> &session) {
    if (!session->session_conn->socket->lowest_layer().is_open()) {
      auto resolver =
          std::make_shared<boost::asio::ip::tcp::resolver>(*io_service);
      session->session_conn->set_timeout(config.timeout_connect);
      resolver->async_resolve(
          host, std::to_string(port),
          [this,
           session](const boost::system::error_code &ec,
                    boost::asio::ip::tcp::resolver::results_type results) {
            session->session_conn->cancel_timeout();
            auto l = scopped_runner->continue_lock(); // stop the process from
                                                      // moving forward at all
            if (!l)
              return;
            if (!ec) {
              session->session_conn->set_timeout(config.timeout_connect);
              boost::asio::async_connect(
                  *session->session_conn->socket, results,
                  [this, session](const boost::system::error_code &ec,
                                  boost::asio::ip::tcp::resolver::endpoint_type
                                      async_connect_endpoint /*endpoint*/) {
                    session->session_conn->cancel_timeout();
                    if (!ec) {
                      this->write(session);
                    } else {
                      session->callback(ec);
                    }
                  });
            } else {
              session->callback(ec);
            }
          });
    } else {
      std::error_code ec;
      std::cout << "Socket error ..." << std::endl;
      throw ec;
    }
  };
  // Client stop
  void stop() {
    scopped_runner->stop();
    std::lock_guard<std::mutex> lock(connection_pool_mutex);
    for (auto it = connections_pool.begin(); it != connections_pool.end();) {
      (*it)->close();
      it = connections_pool.erase(it);
    }
  }
};
