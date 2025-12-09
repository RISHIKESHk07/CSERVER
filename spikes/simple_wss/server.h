#include <bits/stdc++.h>
#include <boost/asio.hpp>
#include <boost/asio/detail/std_fenced_block.hpp>
#include <boost/asio/ssl.hpp>
#include <cstddef>
#include <memory>
#include <string>

class Connection;

class Request {
public:
  boost::asio::streambuf request_buffer;
  std::string version;
  std::string method;
  std::string body;
  std::map<std::string, std::string> request_parsed;
};

class Response {
public:
  Connection *parent_conn = nullptr;
  boost::asio::streambuf response_buffer;
  std::string version;
  void send();
  void write_response(); // write the response status,body ..etc
};

class Connection : std::enable_shared_from_this<Connection> {

public:
  int id;
  std::string name;
  std::shared_ptr<Request> req;
  std::shared_ptr<Response> res;
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> conn_socket;
  boost::asio::streambuf reader;
  Connection(int id, std::string name,
             boost::asio::ssl::stream<boost::asio::ip::tcp::socket> soc)
      : id(id), name(std::to_string(id) + name), conn_socket(std::move(soc)) {
    std::cout << "Connection accepted:" + std::to_string(id) << std::endl;
    res = std::make_shared<Response>();
    req = std::make_shared<Request>();
    res->parent_conn = this;
  };
};

// class forwarding inline function for response obj
inline void Response::send() {

  std::ostream os(&response_buffer);
  os << "HTTP/1.1 200 OK\r\n"
     << "Content-Type: text/plain\r\n"
     << "Content-Length: 11\r\n"
     << "\r\n"
     << "Hello World";

  boost::asio::async_write(
      this->parent_conn->conn_socket, response_buffer,
      [](const boost::system::error_code &ec, std::size_t bytes_transferred) {
        if (!ec) {
          std::cout << "Sent a response message .." << std::endl;
        }
      });
};

class Server {

protected:
  // Variables:
  //  Need asio context
  //  need host & port
  //  a method to send message over the wire
  //  request parser for incoming request over the wire
  //  listen function for accepting connections
  //  workflow
  //  listen -> accept -> parse -> send_response ( http_response )
  boost::asio::io_context io_context;
  std::string host;
  unsigned int port;
  std::optional<std::thread> server_thread;
  boost::asio::ip::tcp::endpoint server_endpoint;
  boost::asio::ip::tcp::acceptor acceptor;
  boost::asio::streambuf request_streambuffer;
  boost::asio::streambuf response_streambuffer;
  std::vector<std::shared_ptr<Connection>> connections_list;
  boost::asio::ssl::context ssl_context{boost::asio::ssl::context::tls_server};
  std::map<std::string,
           std::map<std::string,
                    std::function<void(std::shared_ptr<Request> &req,
                                       std::shared_ptr<Response> &res)>>>
      server_resources;
  std::map<std::string, std::string> ParsedResourceMap;
  std::string path;
  std::string method;
  std::string version;
  std::function<void(std::shared_ptr<Request> &req,
                     std::shared_ptr<Response> &res)>
      default_callback =
          [](std::shared_ptr<Request> &req, std::shared_ptr<Response> &res) {
            std::cout << "404 Page " << std::endl;
          };

  void load_ssl_options() {
    try {
      const char *cert_path = "server.crt";
      const char *key_path = "server.key";
      this->ssl_context.use_certificate_chain_file(cert_path);
      this->ssl_context.use_private_key_file(key_path,
                                             boost::asio::ssl::context::pem);
      std::cout << "SSL OPTIONS Loaded .." << std::endl;
    } catch (const boost::system::error_code &err) {
      std::cout << err.message() << std::endl;
    }
  }

  void listen(int init_id) {
    // Listen logic
    acceptor.async_accept([init_id,
                           this](const boost::system::error_code &error,
                                 boost::asio::ip::tcp::socket peer) {
      if (!error) {
        auto new_conn = std::make_shared<Connection>(
            init_id, "",
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket>(
                std::move(peer), this->ssl_context));
        new_conn->conn_socket.set_verify_mode(boost::asio::ssl::verify_none);
        TLS_handshake_connection_worker(new_conn);
        boost::asio::post(this->io_context, [this, init_id]() mutable {
          auto temp_id = init_id + 1;
          this->listen(temp_id);
        });
      } else {
        std::cout << "[Error at connection acceptance:]" + error.message()
                  << std::endl;
      }
    });
  };
  void read(const std::shared_ptr<Connection> &conn) {
    boost::asio::async_read(
        conn->conn_socket, conn->reader, boost::asio::transfer_at_least(1),
        [this, conn](const boost::system::error_code &error,
                     std::size_t bytes_transferred) {
          if (!error) {

            std::string line(bytes_transferred, ' ');
            std::istream is(&conn->reader);
            is.read(line.data(), bytes_transferred);
            conn->reader.consume(bytes_transferred);
            if (!line.empty())
              request_parser(line);
            // need to make a callback func here for exec the server callback of
            std::cout << line << std::endl;
            if (path.length() != 0) {
              if (requesthandlercallback(path, method, conn->req, conn->res))
                std::cout << "Handler request processed" << std::endl;
              else
                default_callback(conn->req, conn->res);
            }
            // send a simlpe write message
          } else {
            std::cout << "Error at read:" << error.message() << std::endl;
          }
        });
  };

  void request_parser(std::string request_content) {
    // request_parser for query string , content-length ,version
    std::istringstream iss(request_content);
    std::string request_line;
    std::getline(iss, request_line); // first line: GET /index?x=1 HTTP/1.1

    std::string full_path;
    std::istringstream rl(request_line);
    rl >> method >> full_path >> version;
    std::cout << method << "--" << full_path << "--" << version << std::endl;
    // Extract path and query
    auto qpos = full_path.find("?");
    path = (qpos != std::string::npos) ? full_path.substr(0, qpos) : full_path;

    if (qpos != std::string::npos) {
      size_t aepos = full_path.find("=", qpos);
      if (aepos != std::string::npos) {
        std::string line;
        auto cur = qpos + 1;
        while (aepos != std::string::npos) {
          auto apos = full_path.find("&", aepos);
          if (apos == std::string::npos)
            apos = full_path.length();
          auto k1 = full_path.substr(cur, aepos - cur);
          auto v1 = full_path.substr(aepos + 1, apos - aepos - 1);
          cur = apos + 1;
          aepos = full_path.find("=", cur);

          ParsedResourceMap[k1] = v1;
        }
      }
    }
    // header_parsing
    while (std::getline(iss, request_line)) {
      auto e_pos = request_line.find("=");
      ParsedResourceMap[request_line.substr(0, e_pos)] =
          request_line.substr(e_pos + 1, request_line.length() - e_pos - 1);
    }
    // removing the rndline to body
    std::getline(iss, request_line);
  }

  bool requesthandlercallback(std::string &regex, std::string &method,
                              std::shared_ptr<Request> &req,
                              std::shared_ptr<Response> &res) {
    try {
      auto route_checker = server_resources.find(regex);
      if (route_checker == server_resources.end())
        return false;
      auto callback_checker = route_checker->second.find(method);
      if (callback_checker == route_checker->second.end())
        return false;
      auto handler_checker = callback_checker->second;
      if (!handler_checker)
        return false;
      server_resources[regex][method](req, res);
      return 1;
    } catch (std::error_code err) {
      std::cout << err.message() << std::endl;
      return false;
    }
  };

  void TLS_handshake_connection_worker(std::shared_ptr<Connection> &conn) {
    conn->conn_socket.async_handshake(
        boost::asio::ssl::stream_base::server,
        [this, conn](const boost::system::error_code &error) {
          if (!error) {
            this->log_info_tls(conn->conn_socket);
            this->connections_list.push_back(conn);
            this->read(conn);
          } else {
            std::cout << "TLS_handshake failed .." + error.message()
                      << std::endl;
          }
        });
  }
  void log_info_tls(
      boost::asio::ssl::stream<boost::asio::ip::tcp::socket> &tls_socket) {
    SSL *native_handle = tls_socket.native_handle();
    if (native_handle) {
      const char *tls_version = SSL_get_version(native_handle);
      const SSL_CIPHER *tls_cipher = SSL_get_current_cipher(native_handle);
      auto client_cipher = SSL_get_client_ciphers(native_handle);
      std::cout << "TLS Version:" << tls_version << std::endl;
      std::cout << "TLS Cipher:" << SSL_CIPHER_get_name(tls_cipher)
                << std::endl;
    }
  }

public:
  Server(std::string host, unsigned int port)
      : host(host), port(port),
        server_endpoint(boost::asio::ip::make_address_v4(host), port),
        acceptor(io_context) {
    load_ssl_options();
    int init_id = 123;
    // primed the acceptor object
    acceptor.open(boost::asio::ip::tcp::v4());
    acceptor.bind(server_endpoint);
    acceptor.listen();
    // listen
    listen(init_id);
  };
  void run() {
    if (this->acceptor.is_open())
      std::cout << "Acceptor is open" << std::endl;
    server_thread.emplace([this]() { this->io_context.run(); });
  };
  void stop() {
    this->io_context.stop();

    if (server_thread->joinable()) {
      server_thread->join();
    }

    for (auto c : connections_list) {
      boost::system::error_code ec;
      auto e = c->conn_socket.shutdown(ec);
      c->conn_socket.lowest_layer().close();
    }
    connections_list.clear();
    this->acceptor.set_option(
        boost::asio::ip::tcp::acceptor::reuse_address(true));
  };
  void register_handler(
      std::string regex_string, std::string method,
      std::function<void(std::shared_ptr<Request> &, std::shared_ptr<Response>)>
          callbackfunction) {
    server_resources[regex_string][method] = std::move(callbackfunction);
  }
};
