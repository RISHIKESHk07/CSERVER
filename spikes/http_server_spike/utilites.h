#pragma once
#include <bits/stdc++.h>
#include <boost/asio.hpp>
#include <cctype>
#include <cstddef>
#include <istream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>

namespace Utilites {
// asio helper functions
template <typename handler_type>
inline void post(boost::asio::io_context &context, handler_type &&handler) {
  boost::asio::post(context, std::forward<handler_type>(handler));
}
//---------------------------------

// caseinsenstivemultimap for headers string

class CaseInsensitiveEqual {
public:
  static bool CaseInsenstiveEqual(const std::string &str1,
                                  const std::string str2) {
    if (str1.size() != str2.size())
      return false;
    return std::equal(
        str1.begin(), str1.end(), str2.begin(),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); });
  }
  const bool operator()(const std::string &str1,
                        const std::string &str2) const {
    return CaseInsenstiveEqual(str1, str2);
  }
};
class CaseInsensitveHash {
public:
  std::size_t operator()(const std::string &str) const {
    std::size_t h = 0;
    std::hash<int> hash;
    for (auto c : str) {
      h ^= hash(std::tolower(h)) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
  }
};
using CaseInsenstiveMultimap =
    std::unordered_multimap<std::string, std::string, CaseInsensitveHash,
                            CaseInsensitiveEqual>;

// scope_runner
inline void spin_loop_pause() noexcept {
  std::this_thread::sleep_for(std::chrono::nanoseconds(
      50)); // using sleep as mitigation here , requires _mm_pause() , have a
            // issue with clang i suppose
}
class scope_runner {
  std::atomic<bool> stopped = false;
  std::atomic<int> count;

public:
  scope_runner() : count(0) {};
  class Shared_lock {
    std::atomic<int> &count;

  public:
    Shared_lock(std::atomic<int> &c) : count(c) {};
    ~Shared_lock() { count.fetch_sub(1); };
  };
  std::unique_ptr<Shared_lock> continue_lock() {
    int expected = count;
    if (stopped)
      return nullptr;
    while (expected >= 0 &&
           !count.compare_exchange_weak(expected, expected + 1)) {
      if (stopped)
        return nullptr;
      spin_loop_pause();
    }
    if (expected < 0)
      return nullptr;
    return std::unique_ptr<Shared_lock>(new Shared_lock(count));
  }
  void stop() {
    stopped = true;
    int expected = 0;
    while (!count.compare_exchange_weak(expected, -1)) {
      if (expected > 0) {
        expected = 0;
        spin_loop_pause();
      } else
        return;
    }
  }
};
// percent -encode - decode
class Percent {
public:
  static std::string encode(const std::string &str) {
    std::string result;
    static auto hex_chars = "0123456789ABCDEF";
    for (auto &chr : str) {
      if (!((chr >= '0' && chr <= '9') || (chr >= 'A' && chr <= 'Z') ||
            (chr >= 'a' && chr <= 'z') || chr == '-' || chr == '.' ||
            chr == '_' || chr == '~')) {
        result += std::string("%") +
                  hex_chars[static_cast<unsigned char>(chr) / 16] +
                  hex_chars[static_cast<unsigned char>(chr) % 16];
      }
      result += chr;
    }
    return result;
  }
  static std::string decode(std::string &encoded_str) {
    std::string result;
    for (auto i = 0; i < encoded_str.size(); i++) {
      if (encoded_str[i] == '%') {
        auto hex = encoded_str.substr(i + 1, 2);
        auto decoded_chr =
            static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
        result += decoded_chr;
        i += 2;

      } else if (encoded_str[i] == '+') {
        result += " ";
      } else {
        result += encoded_str[i];
      }
    }
    return result;
  }
};
// query_string parse
class QueryString {
public:
  // create a query string
  std::string create_qs(const CaseInsenstiveMultimap &h) {
    std::string result;
    result += "?";
    for (auto &f : h) {
      result += (f.first + "=" + Percent::encode(f.second) + "&");
    }
    result.substr(0, result.size() - 1);
    return result;
  }
  Utilites::CaseInsenstiveMultimap parse(std::string &query_string) {
    Utilites::CaseInsenstiveMultimap result;
    int begin_nkv = 0;
    int equal_nkv = 0;
    int end_nqs = 0;
    for (int i = 0; i < query_string.size(); i++) {
      if (query_string[i] == '?') {
        begin_nkv = i + 1;
      } else if (query_string[i] == '&') {
        auto name = query_string.substr(begin_nkv, (equal_nkv - begin_nkv));
        auto value = query_string.substr(equal_nkv + 1, (end_nqs - equal_nkv));
        result.emplace(std::move(name), std::move(Percent::decode(value)));
        begin_nkv = (i + 1);
      } else if (query_string[i] == '=') {
        equal_nkv = i;
      } else {
        end_nqs++;
      }
    }
    auto name = query_string.substr(begin_nkv, (equal_nkv - begin_nkv));
    auto value = query_string.substr(equal_nkv + 1, (end_nqs - equal_nkv));
    result.emplace(std::move(name), std::move(Percent::decode(value)));

    return result;
  }
};

// http_header_parse
class HTTPHEADER {
public:
  static Utilites::CaseInsenstiveMultimap parse(std::istream &input_istream) {
    CaseInsenstiveMultimap head;
    std::string line;
    size_t separator;
    while (std::getline(input_istream, line) &&
           (separator = line.find(':') != std::string::npos)) {
      auto vs = separator + 1;
      while (vs < line.size() && line[vs] == ' ')
        vs++;
      auto header = line.substr(0, separator - 1);
      auto value =
          line.substr(vs, line.size() - vs - (line.back() == '\r' ? 1 : 0));
      head.emplace(header, value);
    }
    return head;
  }
};

// request parse
class RequestMessage {
public:
  /** Parse request line and header fields from a request stream.
   *
   * @param[in]  stream       Stream to parse.
   * @param[out] method       HTTP method.
   * @param[out] path         Path from request URI.
   * @param[out] query_string Query string from request URI.
   * @param[out] version      HTTP version.
   * @param[out] header       Header fields.
   *
   * @return True if stream is parsed successfully, false if not.
   */
  static bool parse(std::istream &input_stream, std::string &method,
                    std::string &path, std::string &query_string,
                    std::string &http_version,
                    Utilites::CaseInsenstiveMultimap &header) {
    std::string line;
    std::getline(input_stream, line);
    auto l = line.find(' ');
    if (l != std::string::npos) {
      method = line.substr(0, l);
      auto qs_end = line.find(' ', l + 1);
      auto qs_start = line.find('?', 0);
      if (qs_end != std::string::npos) {
        if (qs_start != std::string::npos) {
          path = line.substr(l + 1, qs_start - l - 1);
          query_string = line.substr(qs_start + 1, qs_end - qs_start - 1);
        } else {
          path = line.substr(l + 1, qs_end - l - 1);
        }
        auto protocol_end = line.find('/', qs_end + 1);
        if (protocol_end != std::string::npos) {
          if (line.compare(qs_end + 1, protocol_end - qs_end - 1, "HTTP") !=
              0) {
            http_version =
                line.substr(protocol_end + 1, line.size() - protocol_end - 1);
          } else
            return false;

        } else
          return false;

      } else
        return false;

    } else {
      return false;
    }

    header = HTTPHEADER::parse(input_stream);

    return true;
  };
};
class ResponseMessage {
public:
  /** Parse status line and header fields from a response stream.
   *
   * @param[in]  stream      Stream to parse.
   * @param[out] version     HTTP version.
   * @param[out] status_code HTTP status code.
   * @param[out] header      Header fields.
   *
   * @return True if stream is parsed successfully, false if not.
   */
  static bool parse(std::istream &stream, std::string &version,
                    std::string &status_code,
                    CaseInsenstiveMultimap &header) noexcept {
    std::string line;
    size_t http_end;
    if (std::getline(stream, line) &&
        (http_end = line.find(' ') != std::string::npos)) {
      if (line.size() > 5) {
        version = line.substr(5, http_end - 5);
      }
      return false;
      auto sc_end = line.find(" ", http_end);
      if (sc_end != std::string::npos) {
        status_code = line.substr(http_end + 1, sc_end - http_end - 1);

      } else
        return false;

      header = Utilites::HTTPHEADER::parse(stream);

    } else
      return false;

    return true;
  }
};

// status codes
enum class StatusCode {
  unknown = 0,
  information_continue = 100,
  information_switching_protocols,
  information_processing,
  success_ok = 200,
  success_created,
  success_accepted,
  success_non_authoritative_information,
  success_no_content,
  success_reset_content,
  success_partial_content,
  success_multi_status,
  success_already_reported,
  success_im_used = 226,
  redirection_multiple_choices = 300,
  redirection_moved_permanently,
  redirection_found,
  redirection_see_other,
  redirection_not_modified,
  redirection_use_proxy,
  redirection_switch_proxy,
  redirection_temporary_redirect,
  redirection_permanent_redirect,
  client_error_bad_request = 400,
  client_error_unauthorized,
  client_error_payment_required,
  client_error_forbidden,
  client_error_not_found,
  client_error_method_not_allowed,
  client_error_not_acceptable,
  client_error_proxy_authentication_required,
  client_error_request_timeout,
  client_error_conflict,
  client_error_gone,
  client_error_length_required,
  client_error_precondition_failed,
  client_error_payload_too_large,
  client_error_uri_too_long,
  client_error_unsupported_media_type,
  client_error_range_not_satisfiable,
  client_error_expectation_failed,
  client_error_im_a_teapot,
  client_error_misdirection_required = 421,
  client_error_unprocessable_entity,
  client_error_locked,
  client_error_failed_dependency,
  client_error_upgrade_required = 426,
  client_error_precondition_required = 428,
  client_error_too_many_requests,
  client_error_request_header_fields_too_large = 431,
  client_error_unavailable_for_legal_reasons = 451,
  server_error_internal_server_error = 500,
  server_error_not_implemented,
  server_error_bad_gateway,
  server_error_service_unavailable,
  server_error_gateway_timeout,
  server_error_http_version_not_supported,
  server_error_variant_also_negotiates,
  server_error_insufficient_storage,
  server_error_loop_detected,
  server_error_not_extended = 510,
  server_error_network_authentication_required
};

inline const std::map<StatusCode, std::string> &status_code_strings() {
  static const std::map<StatusCode, std::string> status_code_strings = {
      {StatusCode::unknown, ""},
      {StatusCode::information_continue, "100 Continue"},
      {StatusCode::information_switching_protocols, "101 Switching Protocols"},
      {StatusCode::information_processing, "102 Processing"},
      {StatusCode::success_ok, "200 OK"},
      {StatusCode::success_created, "201 Created"},
      {StatusCode::success_accepted, "202 Accepted"},
      {StatusCode::success_non_authoritative_information,
       "203 Non-Authoritative Information"},
      {StatusCode::success_no_content, "204 No Content"},
      {StatusCode::success_reset_content, "205 Reset Content"},
      {StatusCode::success_partial_content, "206 Partial Content"},
      {StatusCode::success_multi_status, "207 Multi-Status"},
      {StatusCode::success_already_reported, "208 Already Reported"},
      {StatusCode::success_im_used, "226 IM Used"},
      {StatusCode::redirection_multiple_choices, "300 Multiple Choices"},
      {StatusCode::redirection_moved_permanently, "301 Moved Permanently"},
      {StatusCode::redirection_found, "302 Found"},
      {StatusCode::redirection_see_other, "303 See Other"},
      {StatusCode::redirection_not_modified, "304 Not Modified"},
      {StatusCode::redirection_use_proxy, "305 Use Proxy"},
      {StatusCode::redirection_switch_proxy, "306 Switch Proxy"},
      {StatusCode::redirection_temporary_redirect, "307 Temporary Redirect"},
      {StatusCode::redirection_permanent_redirect, "308 Permanent Redirect"},
      {StatusCode::client_error_bad_request, "400 Bad Request"},
      {StatusCode::client_error_unauthorized, "401 Unauthorized"},
      {StatusCode::client_error_payment_required, "402 Payment Required"},
      {StatusCode::client_error_forbidden, "403 Forbidden"},
      {StatusCode::client_error_not_found, "404 Not Found"},
      {StatusCode::client_error_method_not_allowed, "405 Method Not Allowed"},
      {StatusCode::client_error_not_acceptable, "406 Not Acceptable"},
      {StatusCode::client_error_proxy_authentication_required,
       "407 Proxy Authentication Required"},
      {StatusCode::client_error_request_timeout, "408 Request Timeout"},
      {StatusCode::client_error_conflict, "409 Conflict"},
      {StatusCode::client_error_gone, "410 Gone"},
      {StatusCode::client_error_length_required, "411 Length Required"},
      {StatusCode::client_error_precondition_failed, "412 Precondition Failed"},
      {StatusCode::client_error_payload_too_large, "413 Payload Too Large"},
      {StatusCode::client_error_uri_too_long, "414 URI Too Long"},
      {StatusCode::client_error_unsupported_media_type,
       "415 Unsupported Media Type"},
      {StatusCode::client_error_range_not_satisfiable,
       "416 Range Not Satisfiable"},
      {StatusCode::client_error_expectation_failed, "417 Expectation Failed"},
      {StatusCode::client_error_im_a_teapot, "418 I'm a teapot"},
      {StatusCode::client_error_misdirection_required,
       "421 Misdirected Request"},
      {StatusCode::client_error_unprocessable_entity,
       "422 Unprocessable Entity"},
      {StatusCode::client_error_locked, "423 Locked"},
      {StatusCode::client_error_failed_dependency, "424 Failed Dependency"},
      {StatusCode::client_error_upgrade_required, "426 Upgrade Required"},
      {StatusCode::client_error_precondition_required,
       "428 Precondition Required"},
      {StatusCode::client_error_too_many_requests, "429 Too Many Requests"},
      {StatusCode::client_error_request_header_fields_too_large,
       "431 Request Header Fields Too Large"},
      {StatusCode::client_error_unavailable_for_legal_reasons,
       "451 Unavailable For Legal Reasons"},
      {StatusCode::server_error_internal_server_error,
       "500 Internal Server Error"},
      {StatusCode::server_error_not_implemented, "501 Not Implemented"},
      {StatusCode::server_error_bad_gateway, "502 Bad Gateway"},
      {StatusCode::server_error_service_unavailable, "503 Service Unavailable"},
      {StatusCode::server_error_gateway_timeout, "504 Gateway Timeout"},
      {StatusCode::server_error_http_version_not_supported,
       "505 HTTP Version Not Supported"},
      {StatusCode::server_error_variant_also_negotiates,
       "506 Variant Also Negotiates"},
      {StatusCode::server_error_insufficient_storage,
       "507 Insufficient Storage"},
      {StatusCode::server_error_loop_detected, "508 Loop Detected"},
      {StatusCode::server_error_not_extended, "510 Not Extended"},
      {StatusCode::server_error_network_authentication_required,
       "511 Network Authentication Required"}};
  return status_code_strings;
}

std::string status_code_to_string(StatusCode enum_code) {
  auto pos = status_code_strings().find(enum_code);
  if (pos == status_code_strings().end()) {
    return "";
  }
  return pos->second;
}

}; // namespace Utilites
