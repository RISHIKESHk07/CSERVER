#include "../utilites.h"
int main() {
  std::string str =
      "https://www.example.com/"
      "search?query=laptop%20bags&category=electronics&sort=price_asc";
  Utilites::QueryString q;
  auto h = q.parse(str);

  for (auto f : h) {
    std::cout << f.first << "--" << f.second << std::endl;
  }

  return 0;
}
