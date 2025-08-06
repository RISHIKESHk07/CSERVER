#pragma once
#include "common.h"
#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
namespace network_common_utilites {

template <typename T> class ThreadSafeQ {

private:
  std::mutex QM;
  std::deque<T> Q;
  std::condition_variable *cv = nullptr;
  using Iterator = typename std::deque<
      std::shared_ptr<network_common_utilites::Server_ConnectionOBJ>>::iterator;

public:
  ThreadSafeQ(std::condition_variable *cv = nullptr) : cv(cv) {};
  void push_back(T &&arg) {
    std::scoped_lock<std::mutex> lock(QM);
    Q.push_back(std::move(arg));
    if (cv != nullptr)
      cv->notify_one();
  };
  void push_back(T &arg) {
    std::scoped_lock<std::mutex> lock(QM);
    Q.push_back(arg);
    if (cv != nullptr)
      cv->notify_one();
  };
  bool pop_back() {
    std::scoped_lock<std::mutex> lock(QM);
    if (Q.empty())
      return false;
    Q.pop_back();
    return true;
  };
  bool pop_front() {
    std::scoped_lock<std::mutex> lock(QM);
    if (Q.empty())
      return false;
    Q.pop_front();
    return true;
  };
  T &front() {
    std::scoped_lock<std::mutex> lock(QM);
    return Q.front();
  };
  T &back() {
    std::scoped_lock<std::mutex> lock(QM);
    return Q.back();
  }
  bool empty() {
    std::scoped_lock<std::mutex> lock(QM);
    return Q.empty();
  };
  std::size_t size() {
    std::scoped_lock<std::mutex> lock(QM);
    return Q.size();
  };
  Iterator
  find(std::shared_ptr<network_common_utilites::Server_ConnectionOBJ> &obj) {
    std::scoped_lock<std::mutex> lock(QM);
    auto retConn = std::find(Q.begin(), Q.end(), obj);
    return retConn;
  }
  Iterator end() { return Q.end(); }

  bool erase(Iterator it) {
    std::scoped_lock<std::mutex> lock(QM);
    Q.erase(it, Q.end());
    return 1;
  }
  std::vector<T> snapshot() {
    std::scoped_lock<std::mutex> lock(QM);
    return std::vector<T>(Q.begin(), Q.end());
  }
  Iterator remove(const T &item) {
    std::scoped_lock<std::mutex> lock(QM);
    auto it = std::find(Q.begin(), Q.end(), item);
    return Q.erase(it, Q.end());
  }
  template <typename Func> void for_each_operation(Func f) {
    std::scoped_lock<std::mutex> lock(QM);
    for (auto &q : Q) {
      f(q);
    }
  }
};
} // namespace network_common_utilites
