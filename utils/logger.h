#include "iostream"
#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>
class custom_logger {

  enum class TYPES : int32_t {
    EXECPTION,
    INFO,
    DEBUG,
  };
  std::map<int, TYPES> loggMap = {
      {1, TYPES::EXECPTION}, {2, TYPES::INFO}, {3, TYPES::DEBUG}};
  std::string type(enum TYPES ty) {
    switch (ty) {
    case TYPES::EXECPTION:
      return "EXECPTION";
    case TYPES::DEBUG:
      return "DEBUG";
    case TYPES::INFO:
      return "INFO";
    default:
      break;
    }
  }
  enum class USER { SERVER, CLIENT };

public:
  custom_logger() { time_rn = clock(); };
  void log(std::string message, int us, int level) {
    int temp_time = clock();
    // \033[32m
    if (us == 1) {
      std::cout << "[" << type(loggMap[level]) << "]" << "[SERVER]" << "["
                << temp_time << "]:" << message << std::endl;
    }
  }

private:
  std::string save_file_location;
  std::clock_t time_rn;
};
