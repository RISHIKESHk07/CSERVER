#include "client.h"
int main() {
  ClientBase c("127.0.0.1", 8000);
  std::cout << "request sent here ..." << std::endl;
  return 0;
}
