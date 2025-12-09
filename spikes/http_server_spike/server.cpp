#include "server.h"
int main() {
  ServerBase server(8000);
  server.resource["^/get-test$"]["GET"] =
      [](std::shared_ptr<ServerBase::Request> &req,
         std::shared_ptr<ServerBase::Response> &res) {
        std::cout << "pinged" << std::endl;
      };
  server.start();
  return 0;
}
