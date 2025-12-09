#pragma once
#include "bits/stdc++.h"
#include "boost/asio.hpp"
#include "utilites.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/completion_condition.hpp>
#include <boost/asio/executor.hpp>
#include <boost/asio/impl/post.hpp>
#include <boost/asio/impl/read.hpp>
#include <boost/asio/impl/read_until.hpp>
#include <boost/asio/impl/write.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/error_code.hpp>
#include <cstddef>
#include <ios>
#include <istream>
#include <iterator>
#include <memory>
#include <mutex>
#include <ostream>
#include <regex>
#include <set>
#include <string>
#include <system_error>
#include <utility>
class ServerBase {
protected:
  class Connection;
  class Session;

  class Content : public std::istream {
    friend class ServerBase;

  public:
    std::size_t size() const noexcept { return streambuf.size(); }
    /// Convenience function to return content as std::string.
    std::string string() const noexcept {
      return std::string(boost::asio::buffers_begin(streambuf.data()),
                         boost::asio::buffers_end(streambuf.data()));
    }

  private:
    boost::asio::streambuf &streambuf;
    Content(boost::asio::streambuf &streambuf) noexcept
        : std::istream(&streambuf), streambuf(streambuf) {}
  };
  // request class for working wisth HTTP requests recieved from clients
  class Request {
    friend class ServerBase;
    friend class Session;
    Request(std::size_t max_response_streambuf_size,
            const std::shared_ptr<Connection> &connection_)
        : connection(connection_),
          streambuffer(new boost::asio::streambuf(max_response_streambuf_size)),
          content(*streambuffer) {};
    std::unique_ptr<boost::asio::streambuf> streambuffer;
    std::weak_ptr<Connection> connection;

  public:
    Content content;
    std::string http_version;
    std::string status_code;
    std::string query_string;
    std::string method;
    std::string path;
    Utilites::CaseInsenstiveMultimap header;
    std::smatch path_match;
  };

  // connection class
  class Connection : public std::enable_shared_from_this<Connection> {
    friend class ServerBase;
    friend class Session;

  public:
    template <typename... Args>
    Connection(std::shared_ptr<Utilites::scope_runner> handler_runner_,
               boost::asio::io_context &io_co, Args &&...args)
        : Scopped_runner(std::move(handler_runner_)),
          socket(new boost::asio::ip::tcp::socket(io_co)),
          write_strand(
              boost::asio::make_strand(socket->lowest_layer().get_executor())) {
    }

    std::unique_ptr<boost::asio::ip::tcp::socket> socket;
    std::shared_ptr<Utilites::scope_runner> Scopped_runner;
    boost::asio::strand<boost::asio::any_io_executor> write_strand;
    std::shared_ptr<boost::asio::steady_timer> timer;
    void set_timeout(long seconds) noexcept {
      if (seconds == 0) {
        timer = nullptr;
        return;
      }

      timer = std::unique_ptr<boost::asio::steady_timer>(
          new boost::asio::steady_timer(socket->get_executor(),
                                        std::chrono::seconds(seconds)));
      std::weak_ptr<Connection> self_weak(this->shared_from_this());
      timer->async_wait([self_weak](const std::error_code &ec) {
        if (!ec) {
          if (auto self = self_weak.lock())
            self->close();
        }
      });
    }

    void cancel_timeout() noexcept {
      if (timer) {
        try {
          timer->cancel();
        } catch (...) {
        }
      }
    }

    void close() noexcept {
      socket->lowest_layer().shutdown(
          boost::asio::ip::tcp::socket::shutdown_both);
    }
  };
  // session class
  class Session {
    friend class ServerBase;

  public:
    Session(std::size_t max_request_streambuf_size,
            std::shared_ptr<Connection> connection_, int id) noexcept
        : connection(std::move(connection_)), id(id),
          request(new Request(max_request_streambuf_size, connection)) {}
    std::shared_ptr<Connection> connection;
    std::shared_ptr<Request> request;
    int id;
  };
  // config class
  class Config {
    friend class ServerBase;

    Config(unsigned short port) noexcept : port(port) {}

  public:
    /// Port number to use. Defaults to 80 for HTTP and 443 for HTTPS. Set to 0
    /// get an assigned port.
    unsigned short port;
    /// If io_service is not set, number of threads that the server will use
    /// when start() is called. Defaults to 1 thread.
    std::size_t thread_pool_size = 1;
    /// Timeout on request completion. Defaults to 5 seconds.
    long timeout_request = 5;
    /// Timeout on request/response content completion. Defaults to 300 seconds.
    long int timeout_content = 300;
    /// Maximum size of request stream buffer. Defaults to architecture maximum.
    /// Reaching this limit will result in a message_size error code.
    std::size_t max_request_streambuf_size =
        (std::numeric_limits<std::size_t>::max)();
    /// IPv4 address in dotted decimal form or IPv6 address in hexadecimal
    /// notation. If empty, the address will be any address.
    std::string address;
    /// Set to false to avoid binding the socket to an address that is already
    /// in use. Defaults to true.
    bool reuse_address = true;
    /// Make use of RFC 7413 or TCP Fast Open (TFO)
    bool fast_open = false;
  };
  class regex_orderable : public std::regex {
  public:
    std::string str;

    regex_orderable(const char *regex_cstr)
        : std::regex(regex_cstr), str(regex_cstr) {}
    regex_orderable(std::string regex_str_)
        : std::regex(regex_str_), str(std::move(regex_str_)) {}
    bool operator<(const regex_orderable &rhs) const noexcept {
      return str < rhs.str;
    }
  };
  // response class for HTTP responses
  class Response : public std::enable_shared_from_this<Response>,
                   public std::ostream {
    Response(const std::shared_ptr<Session> session_, long timeout_content)
        : std::ostream(nullptr), session_response(session_),
          timeout(timeout_content) {
      this->rdbuf(streambuffer.get());
    };

    friend class ServerBase;

    std::shared_ptr<Session> session_response;
    long timeout;
    std::unique_ptr<boost::asio::streambuf> streambuffer =
        std::unique_ptr<boost::asio::streambuf>(new boost::asio::streambuf());
    std::mutex response_list_mutex;
    std::list<std::pair<std::shared_ptr<boost::asio::streambuf>,
                        std::function<void(const std::error_code &ec)>>>
        response_callbacks_see;

  public:
    // create_header_header
    void create_response_header(const Utilites::CaseInsenstiveMultimap &header,
                                size_t size) {
      bool Transfer_encoding_present = 0;
      bool SSE_present = 0;
      bool CL_present = 0;
      for (auto h : header) {
        if (!Transfer_encoding_present &&
            Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(
                h.first, "Content-length"))
          CL_present = 1;
        if (!Transfer_encoding_present &&
            Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(
                h.first, "Transfer_encoding") &&
            Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(h.second,
                                                                "chunked"))
          Transfer_encoding_present = 1;
        if (!SSE_present &&
            Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(
                h.first, "content-type") &&
            Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(
                h.second, "text/event-stream"))
          SSE_present = 1;
        *this << h.first << ":" << h.second << "\r\n\r\n";
      }
      if (!Transfer_encoding_present && !SSE_present && !CL_present)
        *this << "Content-Length" << ": " << size << "\r\n\r\n";
      else
        *this << "\r\n";
    }
    // send_from_queue for streaming stuff using sse ....
    void send_from_queue() {

      auto msg = response_callbacks_see.begin()->first->data();
      auto self = this->shared_from_this();
      boost::asio::post(
          self->session_response->connection->write_strand, ([self, msg] {
            boost::asio::async_write(
                *self->session_response->connection->socket, msg,
                [self](const boost::system::error_code &error,
                       std::size_t /*bytes_transferred*/) {
                  auto l = self->session_response->connection->Scopped_runner
                               ->continue_lock();
                  if (!l)
                    return;
                  std::unique_lock<std::mutex> lock(self->response_list_mutex);
                  if (!error) {

                    auto it = std::move(self->response_callbacks_see.begin());
                    auto cb = std::move(it->second);
                    self->response_callbacks_see.erase(it);
                    if (self->response_callbacks_see.size() > 0)
                      boost::asio::post([self]() {
                        self->send_from_queue();
                      }); // incase of large number of tasks might stack up fast
                          // and slow the completion of handler completion .
                    lock.unlock();
                    if (cb)
                      cb(error);

                  } else {

                    std::vector<std::function<void(const std::error_code &)>>
                        callbacks;
                    for (auto &c : self->response_callbacks_see) {
                      callbacks.emplace_back(c.second);
                    }
                    self->response_callbacks_see.clear();
                    lock.unlock();
                    for (auto &c1 : callbacks) {
                      c1(error);
                    }
                  }
                });
          }));
    }
    // send function for sse
    void send(std::function<void(const std::error_code &)> callback = nullptr) {
      std::shared_ptr<boost::asio::streambuf> streambuf =
          std::move(this->streambuffer);
      this->streambuffer =
          std::unique_ptr<boost::asio::streambuf>(new boost::asio::streambuf());
      rdbuf(this->streambuffer.get());
      std::unique_lock<std::mutex> lock(response_list_mutex);
      response_callbacks_see.emplace_back(std::move(streambuffer),
                                          std::move(callback));
      lock.unlock();
      if (response_callbacks_see.size() > 0)
        send_from_queue();
    }
    // send delete
    void send_on_delete(
        const std::function<void(const std::error_code &ec)> &callback) {
      // write the streambuffer to the socket ----
      auto self = this->shared_from_this();
      auto data = streambuffer->data();
      boost::asio::post(
          session_response->connection->write_strand, [data, self, callback]() {
            boost::asio::async_write(
                *self->session_response->connection->socket, data,
                [self, callback](const std::error_code &ec,
                                 std::size_t /*bytes_transferred*/) {
                  if (!ec) {
                    if (callback)
                      callback(ec);
                  }
                });
          });
    };
    // write
    void write(Utilites::StatusCode status_code, std::istream &content,
               const Utilites::CaseInsenstiveMultimap &header =
                   Utilites::CaseInsenstiveMultimap()) {
      *this << "HTTP/1.1 " << Utilites::status_code_to_string(status_code)
            << "\r\n";
      content.seekg(0, std::ios::end);
      auto size = content.tellg();
      content.seekg(0, std::ios::beg);
      create_response_header(header, size);
      if (size)
        *this << content.rdbuf();
    }
  };

public:
  Config config;
  boost::asio::io_context server_context;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptorObj;
  std::shared_ptr<Utilites::scope_runner> scope_runner;
  std::unordered_set<std::shared_ptr<Connection>> connection_pool;
  std::mutex connection_pool_mutex;
  std::map<
      regex_orderable,
      std::map<std::string,
               std::function<void(std::shared_ptr<ServerBase::Request> &req,
                                  std::shared_ptr<ServerBase::Response> &res)>>>
      resource;
  std::map<std::string, std::function<void(std::shared_ptr<Request> &req,
                                           std::shared_ptr<Response> &res)>>
      default_resource;
  int client_id;
  void start() {
    std::cout << "Server started ..." << std::endl;
    client_id = 456;
    config.address = "127.0.0.1";
    auto endpoint = boost::asio::ip::tcp::endpoint(
        boost::asio::ip::make_address(config.address), config.port);
    acceptorObj = std::unique_ptr<boost::asio::ip::tcp::acceptor>(
        new boost::asio::ip::tcp::acceptor(server_context));
    try {
      acceptorObj->open(boost::asio::ip::tcp::v4());
    } catch (const std::error_code &err) {
      std::cout << "ISSUE WITH OPENING V4 socket ..." + err.message()
                << std::endl;
      return;
    }
    acceptorObj->bind(endpoint);
    acceptorObj->listen(boost::asio::socket_base::max_listen_connections);
    std::cout << "SERVER:" << config.address << ":" << config.port << std::endl;
    do_accept();
    this->server_context.run();
  };

  std::shared_ptr<Connection>
  create_connection(boost::asio::io_context &io_service) {
    auto conns = this->connection_pool;
    auto connection = std::shared_ptr<Connection>(new Connection(
        this->scope_runner, io_service,
        [conns](Connection *connection) mutable {
          auto sp =
              std::shared_ptr<Connection>(connection, [](Connection *) {});
          auto it = conns.find(sp);
          if (it != conns.end())
            conns.erase(it);
          std::cout << "SERVER:" << "Connection broke / deleted" << std::endl;
          delete connection;
        }));
    this->connection_pool.insert(connection);
    return connection;
  };
  void do_accept() {
    auto new_connection = create_connection(server_context);
    acceptorObj->async_accept(

        *new_connection->socket,
        [this, new_connection](const boost::system::error_code &error) mutable {
          if (!error) {
            auto l = this->scope_runner->continue_lock();
            if (!l)
              return;

            auto new_session =
                std::make_shared<Session>(config.max_request_streambuf_size,
                                          new_connection, this->client_id);
            std::cout << "Client_id" << this->client_id << "..joined"
                      << std::endl;
            this->read(new_session);
          } else {
            std::cout << error.message() << std::endl;
          }
          this->client_id++;
          do_accept();
        });
  }
  void stop() {
    this->scope_runner->stop();
    this->acceptorObj->close();
    std::unique_lock<std::mutex> lock(connection_pool_mutex);
    for (auto &c : this->connection_pool) {
      c->close();
    }
    lock.unlock();
    this->server_context.stop();
  }
  void read(std::shared_ptr<Session> &session) {
    // read the start of the request until the header is done , we need work
    // content-lengt part here , the header handled in the utilites ,possible we
    // get extra bytes as well which will go into the content buffer entirely ,
    // if transfer encoding handle , if sse as well , every process ends with
    // ---- flow below ----
    // findResurce for the called REST point
    // async_read_until  '/r/n/r/n'
    // parse Utilites::request
    // search for content-length
    // case 1  - read the content
    // case 2 - transfer encoding
    // case 3 -  no content to worry about find resource
    // c1 --> we handle the extra content by checking value , num_add = size
    // -bytes_transferred
    boost::asio::async_read_until(
        *session->connection->socket, *session->request->streambuffer,
        "\r\n\r\n",
        [this, session](const boost::system::error_code &e, std::size_t size) {
          auto l = session->connection->Scopped_runner->continue_lock();
          if (!l)
            return;
          if (!e) {
            std::istream istream(session->request->streambuffer.get());

            if (!Utilites::RequestMessage::parse(
                    istream, session->request->method, session->request->path,
                    session->request->query_string,
                    session->request->http_version, session->request->header)) {
              return;
            }
            auto it = session->request->header.find("Content-length");
            size_t content_length = std::stoul(it->second);
            if (it != session->request->header.end()) {
              size_t num_additional =
                  session->request->streambuffer->size() - size;
              if (num_additional > 0) {
                auto &source = *session->request->streambuffer;
                auto &target = session->request->streambuffer;
                // here we are using source.data() because after read_until is
                // done only yhe additional data is left
                target->commit(boost::asio::buffer_copy(
                    target->prepare(std::min(content_length, num_additional)),
                    source.data()));
                source.consume(std::min(content_length, num_additional));
              }
              // their exists more data to be called ...
              if (content_length > num_additional) {
                boost::asio::async_read(
                    *session->connection->socket,
                    *session->request->streambuffer,
                    [this, session](const boost::system::error_code &e,
                                    std::size_t /*size*/) {
                      if (!e) {
                        this->find_resource(session);
                      } else {
                        if (e.message() == "End of file")
                          std::cout << std::to_string(this->client_id) +
                                           "..closed connection"
                                    << std::endl;
                        else {
                          std::cout << "Error while reading ... " + e.message()
                                    << std::endl;
                        }
                      }
                    });
              } else {
                this->find_resource(session);
              }

            } else if ((it = session->request->header.find(
                            "Transfer-encoding")) !=
                           session->request->header.end() &&
                       it->second == "chunked") {
              auto sink = std::make_shared<boost::asio::streambuf>(
                  std::max<std::size_t>(
                      16 + 2, session->request->streambuffer->size()));
              auto &source = *session->request->streambuffer;
              auto &target = *sink;
              target.commit(boost::asio::buffer_copy(
                  target.prepare(source.size()), source.data()));
              source.consume(source.size());

              this->read_chunked_transfer(session, sink);

            } else {
              this->find_resource(session);
            }
          } else {
            std::cout << "Error while reading ... " + e.message() << std::endl;
          }
        });
  }
  void read_chunked_transfer(
      const std::shared_ptr<Session> &session,
      const std::shared_ptr<boost::asio::streambuf> &streambuffer) {
    boost::asio::async_read_until(
        *session->connection->socket, *streambuffer, "\r\n",
        [session, streambuffer, this](const boost::system::error_code &ec,
                                      size_t bytes_transferred) {
          if (!ec) {
            std::istream istream(streambuffer.get());
            std::string line;
            std::getline(istream, line);
            bytes_transferred -= line.size() + 1; // check this out once
            size_t chunk_size = std::stoul(line, 0, 16);
            auto num_additional = streambuffer->size() - bytes_transferred;
            auto bytes_copying = std::min(
                chunk_size,
                num_additional); // min because we need only the data the CLRF
                                 // after that dealt in else cond
            if (bytes_copying > 0) {
              auto &source = *streambuffer;
              auto &target = *session->request->streambuffer;
              target.commit(boost::asio::buffer_copy(
                  target.prepare(bytes_copying), source.data(), bytes_copying));
              source.consume(source.size());
            }
            auto read_next =
                [chunk_size, this](const std::shared_ptr<Session> &session,
                                   const std::shared_ptr<boost::asio::streambuf>
                                       &streambuffer) {
                  if (chunk_size == 0) {
                    if (streambuffer->size() > 0) {
                      auto &source = *streambuffer;
                      auto &target = *session->request->streambuffer;
                      target.commit(boost::asio::buffer_copy(
                          target.prepare(streambuffer->size()), source.data(),
                          streambuffer->size()));
                      source.consume(streambuffer->size());
                    }
                    find_resource(session);
                  } else {
                    this->read_chunked_transfer(session, streambuffer);
                  }
                };
            if (chunk_size > num_additional) {
              boost::asio::async_read(
                  *session->connection->socket, *session->request->streambuffer,
                  boost::asio::transfer_exactly(chunk_size - num_additional),
                  [session, this, streambuffer,
                   read_next](const std::error_code &ec, std::size_t /*size*/) {
                    if (!ec) {
                      boost::asio::streambuf nullbuff;
                      boost::asio::async_read(
                          *session->connection->socket, nullbuff,
                          boost::asio::transfer_exactly(2),
                          [session, streambuffer,
                           read_next](const boost::system::error_code &ec,
                                      std::size_t /*size*/) {
                            if (!ec) {
                              read_next(session, streambuffer);
                            }
                          });
                    } else {
                    }
                  });
            } else if (chunk_size + 2 > num_additional) {
              if (2 + chunk_size - num_additional == 1)
                istream.get();
              boost::asio::streambuf nullbuff;
              boost::asio::async_read(*session->connection->socket, nullbuff,
                                      boost::asio::transfer_exactly(
                                          2 + chunk_size - num_additional),
                                      [read_next, session, streambuffer](
                                          const boost::system::error_code &ec,
                                          std::size_t /*size*/) {
                                        if (!ec) {
                                          read_next(session, streambuffer);
                                        }
                                      });

            } else {
              istream.get();
              istream.get();
            }
          } else {
            std::cout << "Error in reading chunks" << std::endl;
          }
        });
  };
  void find_resource(const std::shared_ptr<Session> &session) {
    for (auto &regex_method : resource) {
      auto it = regex_method.second.find(session->request->method);
      if (it != regex_method.second.end()) {
        std::smatch sm_res;
        if (std::regex_match(session->request->path, sm_res,
                             regex_method.first)) {
          session->request->path_match = std::move(sm_res);
          write(session, it->second);
        }
      }
    }
  };
  void write(const std::shared_ptr<Session> &session,
             std::function<void(std::shared_ptr<ServerBase::Request> &,
                                std::shared_ptr<ServerBase::Response> &)>
                 &resource_function) {

    auto response = std::shared_ptr<ServerBase::Response>(
        new Response(session, config.timeout_content), [this](Response *ptr) {
          auto response = std::shared_ptr<Response>(ptr);
          response->send_on_delete([this, response](const std::error_code &ec) {
            if (!ec) {
              auto range =
                  response->session_response->request->header.equal_range(
                      "Connection");
              for (auto it = range.first; it != range.second; it++) {
                if (Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(
                        it->second, "close"))
                  return;
                else if (Utilites::CaseInsensitiveEqual::CaseInsenstiveEqual(
                             it->second, "keep-alive")) {
                  auto new_session = std::make_shared<Session>(
                      this->config.max_request_streambuf_size,
                      response->session_response->connection, this->client_id);
                  this->read(new_session);
                }
              }
              if (response->session_response->request->http_version >= "1.1") {
                auto new_session = std::make_shared<Session>(
                    this->config.max_request_streambuf_size,
                    response->session_response->connection, this->client_id);
                this->read(new_session);
              }
            } else {
              std::cout << ec.message() << std::endl;
            }
          });
        });
    try {

      resource_function(session->request, response);

    } catch (std::error_code ec) {
      std::cout << ec.message() << std::endl;
    }
  };

  ServerBase(unsigned int port)
      : config(port), scope_runner(new Utilites::scope_runner()) {
    std::cout << "Server intialized ..." << std::endl;
  };
  ~ServerBase() {
    std::cout << "Stopping the server ..." << std::endl;
    stop();
  };
};
