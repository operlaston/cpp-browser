#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <map>
#include <string>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHUNK_SIZE (4096)

typedef struct {
  std::string scheme;
  std::string host;
  std::string route;
  std::string port;
} Request;

typedef struct {
  std::map<std::string, std::string> headers;
  std::string body;
} Response;

int read_wrapper(int fd, SSL *ssl, char *buf, size_t size, std::string scheme) {
  if (scheme == "http") {
    return read(fd, buf, size);
  }
  return SSL_read(ssl, buf, size);
}

int write_wrapper(int fd, SSL *ssl, const char *buf, size_t size, std::string scheme) {
  if (scheme == "http") {
    return write(fd, buf, size);
  }
  return SSL_write(ssl, buf, size);
}

int write_all(int fd, SSL *ssl, const char *buf, size_t size, std::string scheme) {
  while (size > 0) {
    ssize_t bytes_written = write_wrapper(fd, ssl, buf, size, scheme);
    if (bytes_written < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("write");
      return -1;
    }
    size -= bytes_written;
    buf += bytes_written;
  }
  return 0;
}


int parse_url(std::string &url, Request &req) {
  size_t host_start_i = url.find("://");
  req.scheme = url.substr(0, host_start_i);
  if (host_start_i == std::string::npos) {
    printf("bad url");
    return -1;
  }
  host_start_i += 3;
  size_t host_end_i = url.find("/", host_start_i);
  if (host_end_i == std::string::npos) {
    req.route = "/";
    req.host = url.substr(host_start_i);
  }
  else {
    req.route = url.substr(host_end_i);
    req.host = url.substr(host_start_i, host_end_i - host_start_i);
  }
  size_t port_start = req.host.find(":");
  if (port_start != std::string::npos) {
    port_start++;
    size_t port_end = req.host.find("/");
    req.port = req.host.substr(port_start, port_end - port_start);
    req.host = req.host.substr(0, port_start - 1);
  }
  return 0;
}

void attach_header(std::string &request, std::string header, std::string value) {
  request +=  header + ": " + value + "\r\n";
}

int send_get_request(int fd, SSL *ssl, Request &req) {
  std::string request = "GET " + req.route + " HTTP/1.1\r\n";
  attach_header(request, "Host", req.host);
  attach_header(request, "Connection", "close");
  attach_header(request, "User-Agent", "operlaston");
  request += "\r\n";
  
  printf("Request\n");
  printf("%s\n", request.c_str());
  if (write_all(fd, ssl, request.c_str(), request.size(), req.scheme) < 0) {
    return -1;
  }
  return 0;
}

void parse_response_headers(std::map<std::string, std::string> &header_map, std::string &headers) {
  assert(headers.find("\r\n") != std::string::npos);
  // ignore status line
  std::string curr = headers.substr(headers.find("\r\n") + 2);
  size_t end;
  while ((end = curr.find("\r\n")) != std::string::npos) {
    size_t delimiter = curr.find(": ");
    if (delimiter == std::string::npos) {
      break;
    }
    // delimiter + 2 to ignore the space
    header_map[curr.substr(0, delimiter)] = curr.substr(delimiter + 2, end - (delimiter + 2));
    curr = curr.substr(end + 2);
  }
}

int read_response(int fd, SSL *ssl, char *buf, Response &response, std::string scheme) {
  ssize_t n = 0; 
  size_t headers_end;
  std::string headers;
  while ((n = read_wrapper(fd, ssl, buf, CHUNK_SIZE, scheme)) > 0) {
    buf[n] = 0;
    headers.append(buf, n);
    headers_end = headers.find("\r\n\r\n");
    if (headers_end != std::string::npos) {
      break;
    }
  }
  if (n < 0) {
    perror("read");
    return -1;
  }
  std::string leftover = headers.substr(headers_end + 4);
  headers = headers.substr(0, headers_end);
  parse_response_headers(response.headers, headers);

  printf("Response\n");
  printf("%s\r\n\r\n", headers.c_str());

  if (response.headers.find("Content-Length") != response.headers.end()) {
    unsigned long content_len = std::stoul(response.headers["Content-Length"]);

    content_len -= leftover.size();
    response.body = leftover;
    while (content_len > 0) {
      n = read_wrapper(fd, ssl, buf, CHUNK_SIZE, scheme);
      buf[n] = 0;
      response.body.append(buf, n);
      content_len -= n;
    }
  }

  return 0;
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    printf("Usage: ./browser [url]");
    return -1;
  }

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Failed to create SSL context\n");
    return -1;
  }

  std::string url = argv[1];
  Request req = {};
  if (parse_url(url, req) < 0) {
    return -1;
  }
  assert(req.scheme == "http" || req.scheme == "https");
  if (req.port.empty()) {
    req.port = req.scheme == "http" ? "80" : "443";
  }
  printf("host: %s\n", req.host.c_str());
  printf("port: %s\n", req.port.c_str());
  printf("route: %s\n", req.route.c_str());

  int conn_fd = socket(AF_INET, SOCK_STREAM, 0);
  struct addrinfo hints = { 0 };
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  struct addrinfo *res;
  int err = getaddrinfo(req.host.c_str(), req.port.c_str(), &hints, &res);
  if (err < 0) {
    perror("getaddrinfo");
    return -1;
  }
  if (res == NULL) {
    printf("server not found\n");
    return -1;
  }
  err = connect(conn_fd, res->ai_addr, sizeof(*(res->ai_addr)));
  if (err < 0) {
    perror("connect");
    return -1;
  }
  freeaddrinfo(res);
  printf("connected to %s\n", req.host.c_str());
  
  SSL *ssl = NULL;
  if (req.scheme == "https") {
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, conn_fd);
    if (SSL_connect(ssl) <= 0) {
      perror("failed ssl handshake");
      ERR_print_errors_fp(stderr);
      return -1;
    }
  }

  send_get_request(conn_fd, ssl, req);

  char buf[CHUNK_SIZE + 1] = { 0 };
  Response response = {};
  read_response(conn_fd, ssl, buf, response, req.scheme);

  bool in_tag = false;
  for (auto &c : response.body) {
    if (c == '<') {
      in_tag = true;
    }
    else if (c == '>') {
      in_tag = false;
    }
    else if (!in_tag) {
      printf("%c", c);
    }
  }

  // cleanup
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  close(conn_fd);
  SSL_CTX_free(ctx);
  return 0;
}
