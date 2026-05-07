#include <mylib/landlock.h>
#include <mylib/no_new_privs.h>
#include <mylib/seccomp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

static constexpr int PORT = 8080;
static constexpr int BACKLOG = 16;

std::string mime_type(fs::path const& path)
{
	auto ext = path.extension().string();

	if (ext == ".html" || ext == ".htm") return "text/html";
	if (ext == ".css") return "text/css";
	if (ext == ".js") return "application/javascript";
	if (ext == ".png") return "image/png";
	if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
	if (ext == ".gif") return "image/gif";
	if (ext == ".txt") return "text/plain";

	return "application/octet-stream";
}

void send_all(int fd, std::string const& data)
{
	const char* ptr = data.data();
	std::size_t left = data.size();

	while (left > 0) {
		ssize_t written = send(fd, ptr, left, 0);

		if (written < 0) {
			if (errno == EINTR) {
				continue;
			}

			return;
		}

		ptr += written;
		left -= static_cast<std::size_t>(written);
	}
}

void send_response(
	int client_fd,
	int status,
	std::string const& status_text,
	std::string const& content_type,
	std::string const& body
)
{
	std::ostringstream header;

	header << "HTTP/1.1 " << status << ' ' << status_text << "\r\n";
	header << "Content-Length: " << body.size() << "\r\n";
	header << "Content-Type: " << content_type << "\r\n";
	header << "Connection: close\r\n";
	header << "\r\n";

	send_all(client_fd, header.str());
	send_all(client_fd, body);
}

void send_error(int client_fd, int status, std::string const& status_text)
{
	std::string body =
		"<!doctype html><html><body><h1>" +
		std::to_string(status) + " " + status_text +
		"</h1></body></html>\n";

	send_response(client_fd, status, status_text, "text/html", body);
}

std::string url_decode(std::string_view input)
{
	std::string out;

	for (std::size_t i = 0; i < input.size(); ++i) {
		if (input[i] == '%' && i + 2 < input.size()) {
			char hex[3] = {input[i + 1], input[i + 2], '\0'};
			char* end = nullptr;
			long value = std::strtol(hex, &end, 16);

			if (*end == '\0') {
				out.push_back(static_cast<char>(value));
				i += 2;
				continue;
			}
		}

		if (input[i] == '+') {
			out.push_back(' ');
		} else {
			out.push_back(input[i]);
		}
	}

	return out;
}

void handle_client(int client_fd)
{
	char buffer[4096];

	ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
	if (n <= 0) {
		return;
	}

	buffer[n] = '\0';

	std::istringstream request(buffer);

	std::string method;
	std::string target;
	std::string version;

	request >> method >> target >> version;

	if (method != "GET") {
		send_error(client_fd, 405, "Method Not Allowed");
		return;
	}

	if (target.empty() || target[0] != '/') {
		send_error(client_fd, 400, "Bad Request");
		return;
	}

	auto query_pos = target.find('?');
	if (query_pos != std::string::npos) {
		target.erase(query_pos);
	}

	std::string decoded = url_decode(target);

	if (decoded.find('\0') != std::string::npos) {
		send_error(client_fd, 400, "Bad Request");
		return;
	}

	fs::path root = fs::weakly_canonical("www");
	fs::path requested = decoded.substr(1);

	if (requested.empty()) {
		requested = "index.html";
	}

	fs::path full_path = fs::weakly_canonical(root / requested);

	auto root_str = root.string();
	auto full_str = full_path.string();

	if (!full_str.starts_with(root_str)) {
		send_error(client_fd, 403, "Forbidden");
		return;
	}

	if (fs::is_directory(full_path)) {
		full_path /= "index.html";
	}

	if (!fs::exists(full_path) || !fs::is_regular_file(full_path)) {
		send_error(client_fd, 404, "Not Found");
		return;
	}

	std::ifstream file(full_path, std::ios::binary);
	if (!file) {
		send_error(client_fd, 403, "Forbidden");
		return;
	}

	std::ostringstream contents;
	contents << file.rdbuf();

	send_response(
		client_fd,
		200,
		"OK",
		mime_type(full_path),
		contents.str()
	);
}

[[noreturn]] void die(int why) noexcept
{
	std::cerr << "error: " << std::strerror(why) << '\n';
	std::exit(1);
}

template <class T>
T unwrap_or_die(std::expected<T, int>&& result)
{
	if (!result) {
		die(result.error());
	}

	return std::move(result).value();
}

inline void unwrap_or_die(std::expected<void, int>&& result)
{
	if (!result) {
		die(result.error());
	}
}


int main()
{
	unwrap_or_die(mylib::set_no_new_privs());

	auto seccomp = unwrap_or_die(mylib::SeccompBuilder::init());

	unwrap_or_die(seccomp.allow("file_system"));
	unwrap_or_die(seccomp.allow("io"));
	unwrap_or_die(seccomp.allow("network_io"));
	unwrap_or_die(unwrap_or_die(seccomp.build()).view().apply());

	auto landlock = unwrap_or_die(mylib::LandlockRuleSet::init());

	unwrap_or_die(landlock.add_rule("www", mylib::LandlockAccess::Read));
	unwrap_or_die(landlock.apply());

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		std::cerr << "socket: " << std::strerror(errno) << '\n';
		return 1;
	}

	int yes = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
		std::cerr << "bind: " << std::strerror(errno) << '\n';
		close(server_fd);
		return 1;
	}

	if (listen(server_fd, BACKLOG) < 0) {
		std::cerr << "listen: " << std::strerror(errno) << '\n';
		close(server_fd);
		return 1;
	}

	std::cout << "Serving www/ at http://127.0.0.1:" << PORT << "/\n";

	while (true) {
		int client_fd = accept(server_fd, nullptr, nullptr);

		if (client_fd < 0) {
			if (errno == EINTR) {
				continue;
			}

			std::cerr << "accept: " << std::strerror(errno) << '\n';
			continue;
		}

		handle_client(client_fd);
		close(client_fd);
	}

	close(server_fd);
	return 0;
}
