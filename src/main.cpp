// SPDX-License-Identifier: MIT
// cpp-protocols-watch — Linux kernel socket-protocol table (/proc/net/protocols)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o protocols-watch
// Usage: ./protocols-watch [--active] [--family NAME] [--name PREFIX] [--press]
//                         [--slab] [--top N] [--watch N] [--json] [--demo]
//                         [--file PATH] [--ops] [--no-color] [--selftest]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

// proto_ops flags as printed by net/core/sock.c proto_seq_show (18 columns)
static const char* kOpsNames[18] = {
  "cl", "co", "di", "ac", "io", "in", "de", "sh",
  "ss", "gs", "se", "re", "bi", "br", "ha", "uh", "gp", "em"
};
static const char* kOpsLong[18] = {
  "close", "connect", "disconnect", "accept", "ioctl", "init", "destroy", "shutdown",
  "setsockopt", "getsockopt", "sendmsg", "recvmsg", "bind", "backlog_rcv",
  "hash", "unhash", "get_port", "enter_memory_pressure"
};

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────
struct Proto {
  std::string name;
  long size = 0;            // obj_size (bytes per sock)
  long sockets = 0;         // sock_prot_inuse_get
  long memory = -1;         // allocated memory, or -1 if proto has no counter
  std::string press;        // "NI" (no indicator) / "no" / "yes"
  long maxhdr = 0;
  bool slab = false;
  std::string module;       // typically "kernel"
  std::string ops;          // 18 chars of y/n (no spaces)
  std::string family;       // ipv4 / ipv6 / unix / netlink / packet / xdp / mctp / other

  int ops_yes() const {
    int n = 0;
    for (char c : ops) if (c == 'y' || c == 'Y') ++n;
    return n;
  }
  bool has_pressure() const { return press == "yes"; }
  bool is_active() const { return sockets > 0; }
};

struct Snapshot {
  long long ts = 0;
  std::vector<Proto> protos;

  std::size_t active() const {
    return static_cast<std::size_t>(
      std::count_if(protos.begin(), protos.end(), [](const Proto& p) { return p.is_active(); }));
  }
  long total_sockets() const {
    long n = 0;
    for (const auto& p : protos) n += p.sockets;
    return n;
  }
  long total_memory() const {
    long n = 0;
    for (const auto& p : protos) if (p.memory > 0) n += p.memory;
    return n;
  }
  int pressure_count() const {
    int n = 0;
    for (const auto& p : protos) if (p.has_pressure()) ++n;
    return n;
  }
  int slab_count() const {
    int n = 0;
    for (const auto& p : protos) if (p.slab) ++n;
    return n;
  }
  std::map<std::string, std::size_t> by_family() const {
    std::map<std::string, std::size_t> m;
    for (const auto& p : protos) ++m[p.family];
    return m;
  }
  const Proto* find(std::string_view name) const {
    for (const auto& p : protos) if (p.name == name) return &p;
    return nullptr;
  }
};

struct Filters {
  bool active = false;          // sockets > 0
  bool press = false;           // only memory-pressure=yes
  bool slab = false;            // only slab-backed
  bool json = false;
  bool demo = false;
  bool color = true;
  bool show_ops = false;
  std::string family;           // ipv4/ipv6/unix/...
  std::string name;             // prefix match (case-sensitive, kernel names)
  std::string file;
  int top = 0;
  int watch = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static long long now_secs() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::optional<long long> parse_ll(std::string_view s, int base = 10) {
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return std::nullopt;
  s.remove_prefix(start);
  long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc()) return std::nullopt;
  if (ptr != s.data() + s.size()) return std::nullopt;
  return v;
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return std::string(s);
}

static std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(s)};
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

static std::string pad(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return s + std::string(w - s.size(), ' ');
}
static std::string padl(std::string s, std::size_t w) {
  if (s.size() >= w) return s;
  return std::string(w - s.size(), ' ') + s;
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\t': o += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
    }
  }
  return o;
}

static std::string classify_family(std::string_view name) {
  if (name == "TCP" || name == "UDP" || name == "RAW" || name == "PING" ||
      name == "UDP-Lite" || name == "MPTCP")
    return "ipv4";
  if (name == "TCPv6" || name == "UDPv6" || name == "RAWv6" || name == "PINGv6" ||
      name == "UDPLITEv6" || name == "MPTCPv6")
    return "ipv6";
  if (name == "UNIX" || name == "UNIX-STREAM")
    return "unix";
  if (name == "NETLINK") return "netlink";
  if (name == "PACKET")  return "packet";
  if (name == "XDP")     return "xdp";
  if (name == "MCTP")    return "mctp";
  return "other";
}

static std::string decode_ops(std::string_view ops) {
  std::string out;
  for (std::size_t i = 0; i < ops.size() && i < 18; ++i) {
    if (ops[i] == 'y' || ops[i] == 'Y') {
      if (!out.empty()) out += '|';
      out += kOpsNames[i];
    }
  }
  return out;
}

static bool dump_to_file(const std::string& path, std::string_view body) {
  std::ofstream f(path);
  if (!f) return false;
  f << body;
  return static_cast<bool>(f);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser — /proc/net/protocols
//   protocol  size sockets  memory press maxhdr  slab module     cl co ... em
//   TCP       2304     22       0   no     320   yes  kernel      y  y ... y
// Comments (#), blank lines and the header row are skipped.
// ─────────────────────────────────────────────────────────────────────────────
static bool parse_protocols_file(const std::string& path, Snapshot& snap) {
  std::ifstream f(path);
  if (!f) return false;
  std::string line;
  while (std::getline(f, line)) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') continue;
    auto tok = split_ws(t);
    if (tok.empty()) continue;
    if (tok[0] == "protocol") continue;          // header
    if (tok.size() < 8) continue;                // malformed
    Proto p;
    p.name = tok[0];
    if (auto v = parse_ll(tok[1])) p.size = static_cast<long>(*v); else continue;
    if (auto v = parse_ll(tok[2])) p.sockets = static_cast<long>(*v); else continue;
    if (auto v = parse_ll(tok[3])) p.memory = static_cast<long>(*v); else continue;
    p.press = tok[4];
    if (auto v = parse_ll(tok[5])) p.maxhdr = static_cast<long>(*v); else continue;
    p.slab = (tok[6] == "yes" || tok[6] == "y");
    p.module = tok[7];
    std::string ops;
    for (std::size_t i = 8; i < tok.size() && ops.size() < 18; ++i) {
      if (tok[i].empty()) continue;
      char c = tok[i][0];
      if (c == 'y' || c == 'Y' || c == 'n' || c == 'N') ops.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    p.ops = ops;
    p.family = classify_family(p.name);
    snap.protos.push_back(std::move(p));
  }
  return true;
}

static bool load_snapshot(Snapshot& snap, const std::string& path) {
  snap.protos.clear();
  bool ok = parse_protocols_file(path, snap);
  std::stable_sort(snap.protos.begin(), snap.protos.end(),
                   [](const Proto& a, const Proto& b) {
                     if (a.sockets != b.sockets) return a.sockets > b.sockets;
                     return a.name < b.name;
                   });
  return ok;
}

static bool passes(const Proto& p, const Filters& f) {
  if (f.active && !p.is_active()) return false;
  if (f.press && !p.has_pressure()) return false;
  if (f.slab && !p.slab) return false;
  if (!f.family.empty() && p.family != f.family) return false;
  if (!f.name.empty()) {
    if (p.name.size() < f.name.size() || p.name.compare(0, f.name.size(), f.name) != 0)
      return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo — synthetic busy host (18 protocols, kernel table format)
// ─────────────────────────────────────────────────────────────────────────────
static const char* DEMO_TABLE =
  "protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re bi br ha uh gp em\n"
  "# comment line tolerated\n"
  "PACKET    1536      2      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n"
  "MPTCPv6   2096      1       0   no       0   yes  kernel      y  y  y  n  y  y  y  y  y  y  y  y  n  n  y  y  y  n\n"
  "PINGv6    1184      0      -1   NI       0   yes  kernel      y  y  y  n  n  y  n  n  y  y  y  y  y  y  y  y  y  n\n"
  "RAWv6     1184      0      -1   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  y  y  y  y  n  n\n"
  "UDPLITEv6 1344      0       0   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  n  n  y  y  y  n\n"
  "UDPv6     1344      4       0   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  n  n  y  y  y  n\n"
  "TCPv6     2496     31       0   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n"
  "XDP        960      0      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n"
  "UNIX-STREAM 1024    48      -1   NI       0   yes  kernel      y  n  n  n  n  n  n  n  n  n  n  n  n  n  n  y  n  n\n"
  "UNIX      1024     14      -1   NI       0   yes  kernel      y  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n"
  "UDP-Lite  1152      0       0   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  n  n  y  y  y  n\n"
  "MPTCP     1936      2       0   no       0   yes  kernel      y  y  y  n  y  y  y  y  y  y  y  y  n  n  y  y  y  n\n"
  "PING       976      1      -1   NI       0   yes  kernel      y  y  y  n  n  y  n  n  y  y  y  y  y  y  y  y  y  n\n"
  "RAW        984      0      -1   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  y  y  y  y  n  n\n"
  "UDP       1152      6    8192   no       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  n  n  y  y  y  n\n"
  "TCP       2304     88   16384  yes     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n"
  "MCTP       816      0      -1   NI       0   no   kernel      y  n  n  n  n  y  n  n  n  n  n  n  n  n  y  y  n  n\n"
  "NETLINK   1080     11      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n";

static bool demo_load(Snapshot& snap) {
  std::string path = "/tmp/protocols-watch-demo.table";
  if (!dump_to_file(path, DEMO_TABLE)) return false;
  bool ok = load_snapshot(snap, path);
  std::remove(path.c_str());
  return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render
// ─────────────────────────────────────────────────────────────────────────────
static std::string family_color(std::string_view fam) {
  if (fam == "ipv4")    return C_GREEN;
  if (fam == "ipv6")    return C_CYAN;
  if (fam == "unix")    return C_YELLOW;
  if (fam == "netlink") return C_MAGENTA;
  if (fam == "packet")  return C_BLUE;
  if (fam == "xdp")     return C_RED;
  return C_DIM;
}

static void render_snapshot(const Snapshot& s, const Filters& f, bool watch_hdr) {
  std::vector<const Proto*> rows;
  for (const auto& p : s.protos) if (passes(p, f)) rows.push_back(&p);
  if (f.top > 0 && static_cast<int>(rows.size()) > f.top)
    rows.resize(static_cast<std::size_t>(f.top));

  long shown_socks = 0;
  for (const auto* p : rows) shown_socks += p->sockets;

  if (watch_hdr) {
    std::cout << "\x1b[2J\x1b[H";
  }

  std::cout << C_BOLD << "-- Kernel protocol table  /proc/net/protocols --" << C_RESET << "\n";
  std::cout << "  " << C_DIM << "protocols " << C_RESET << C_CYAN << s.protos.size() << C_RESET
            << "  " << C_DIM << "active " << C_RESET << C_GREEN << s.active() << C_RESET
            << "  " << C_DIM << "sockets " << C_RESET << C_YELLOW << s.total_sockets() << C_RESET
            << "  " << C_DIM << "memory " << C_RESET << s.total_memory()
            << "  " << C_DIM << "press " << C_RESET
            << (s.pressure_count() ? C_RED : C_DIM) << s.pressure_count() << C_RESET
            << "  " << C_DIM << "slab " << C_RESET << s.slab_count()
            << "\n";

  auto fam = s.by_family();
  std::cout << "  " << C_DIM << "families:" << C_RESET;
  for (const auto& [k, n] : fam) {
    std::cout << "  " << family_color(k) << k << C_RESET << "=" << n;
  }
  std::cout << "\n";
  std::cout << "  " << C_DIM << "source: " << C_RESET
            << (f.demo ? "demo (synthetic busy host)" : (f.file.empty() ? "/proc/net/protocols" : f.file))
            << "   shown " << rows.size() << "/" << s.protos.size()
            << "  socks " << shown_socks << "\n\n";

  std::cout << C_DIM
            << "  proto          family     size  socks    memory  press  maxhdr  slab  module   ops"
            << C_RESET << "\n";
  std::cout << C_DIM
            << "  -------------------------------------------------------------------------------------"
            << C_RESET << "\n";

  for (const auto* p : rows) {
    std::string mem = (p->memory < 0) ? "-" : std::to_string(p->memory);
    std::string press_col = p->has_pressure() ? C_RED : (p->press == "NI" ? C_DIM : C_GREEN);
    std::string sock_col  = p->is_active() ? C_GREEN : C_DIM;
    char opsbuf[16];
    std::snprintf(opsbuf, sizeof(opsbuf), "%d/18", p->ops_yes());

    std::cout << "  " << C_BOLD << pad(p->name, 14) << C_RESET
              << " " << family_color(p->family) << pad(p->family, 8) << C_RESET
              << " " << padl(std::to_string(p->size), 7)
              << " " << sock_col << padl(std::to_string(p->sockets), 6) << C_RESET
              << " " << padl(mem, 9)
              << " " << press_col << pad(p->press, 6) << C_RESET
              << " " << padl(std::to_string(p->maxhdr), 7)
              << "  " << (p->slab ? C_CYAN : C_DIM) << (p->slab ? "yes " : "no  ") << C_RESET
              << " " << pad(p->module, 8)
              << " " << opsbuf;
    if (f.show_ops) {
      std::cout << "  " << C_DIM << decode_ops(p->ops) << C_RESET;
    }
    std::cout << "\n";
  }
  std::cout << std::flush;
}

static void render_json(std::ostream& os, const Snapshot& s, bool demo) {
  os << "{\n  \"summary\": {\n";
  os << "    \"protocols\": " << s.protos.size() << ",\n";
  os << "    \"active\": " << s.active() << ",\n";
  os << "    \"sockets\": " << s.total_sockets() << ",\n";
  os << "    \"memory\": " << s.total_memory() << ",\n";
  os << "    \"pressure\": " << s.pressure_count() << ",\n";
  os << "    \"slab\": " << s.slab_count() << ",\n";
  os << "    \"ts\": " << s.ts << ",\n";
  os << "    \"source\": \"" << (demo ? "demo" : "proc") << "\"\n";
  os << "  },\n  \"protocols\": [\n";
  for (std::size_t i = 0; i < s.protos.size(); ++i) {
    const auto& p = s.protos[i];
    os << "    {\"name\": \"" << json_escape(p.name) << "\""
       << ", \"family\": \"" << json_escape(p.family) << "\""
       << ", \"size\": " << p.size
       << ", \"sockets\": " << p.sockets
       << ", \"memory\": " << p.memory
       << ", \"press\": \"" << json_escape(p.press) << "\""
       << ", \"maxhdr\": " << p.maxhdr
       << ", \"slab\": " << (p.slab ? "true" : "false")
       << ", \"module\": \"" << json_escape(p.module) << "\""
       << ", \"ops\": \"" << json_escape(p.ops) << "\""
       << ", \"ops_yes\": " << p.ops_yes()
       << "}";
    if (i + 1 < s.protos.size()) os << ",";
    os << "\n";
  }
  os << "  ]\n}\n";
}

static void render_delta(const Snapshot& prev, const Snapshot& cur, const Filters& f) {
  std::map<std::string, long> prev_s, cur_s;
  for (const auto& p : prev.protos) if (passes(p, f)) prev_s[p.name] = p.sockets;
  for (const auto& p : cur.protos)  if (passes(p, f)) cur_s[p.name]  = p.sockets;
  int born = 0, died = 0, grew = 0, shrank = 0;
  for (const auto& [k, v] : cur_s) {
    if (!prev_s.contains(k)) ++born;
    else if (v > prev_s[k]) ++grew;
    else if (v < prev_s[k]) ++shrank;
  }
  for (const auto& [k, v] : prev_s) if (!cur_s.contains(k)) ++died;
  std::cout << C_DIM << "  delta vs previous: "
            << C_GREEN << "+" << born << " new  "
            << C_RED << "-" << died << " gone  "
            << C_CYAN << grew << " grew  "
            << shrank << " shrank  "
            << "socks " << cur.total_sockets() << C_RESET
            << (born + died + grew + shrank == 0 ? "  (stable)" : "")
            << "\n\n";
  std::cout << std::flush;
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
  if (ok) { ++g_pass; } else { ++g_fail; std::cout << "    FAIL  " << what << "\n"; }
}

static int selftest() {
  std::cout << "== family classifier ==\n";
  check(classify_family("TCP") == "ipv4", "TCP -> ipv4");
  check(classify_family("UDP-Lite") == "ipv4", "UDP-Lite -> ipv4");
  check(classify_family("MPTCP") == "ipv4", "MPTCP -> ipv4");
  check(classify_family("TCPv6") == "ipv6", "TCPv6 -> ipv6");
  check(classify_family("UDPLITEv6") == "ipv6", "UDPLITEv6 -> ipv6");
  check(classify_family("MPTCPv6") == "ipv6", "MPTCPv6 -> ipv6");
  check(classify_family("UNIX") == "unix", "UNIX -> unix");
  check(classify_family("UNIX-STREAM") == "unix", "UNIX-STREAM -> unix");
  check(classify_family("NETLINK") == "netlink", "NETLINK -> netlink");
  check(classify_family("PACKET") == "packet", "PACKET -> packet");
  check(classify_family("XDP") == "xdp", "XDP -> xdp");
  check(classify_family("MCTP") == "mctp", "MCTP -> mctp");
  check(classify_family("FOO") == "other", "unknown -> other");

  std::cout << "== ops decode ==\n";
  check(decode_ops("nnnnnnnnnnnnnnnnnn").empty(), "all-n ops empty");
  check(decode_ops("ynnnnnnnnnnnnnnnnn") == "cl", "first flag cl");
  check(decode_ops("yyyyyyyyyyyyyyyyyy").find("em") != std::string::npos, "all-y includes em");
  {
    std::string d = decode_ops("yynyynyynyyyyynyyn");
    check(d.find("cl") != std::string::npos && d.find("ac") != std::string::npos, "mixed flags contain cl+ac");
  }
  check(std::string(kOpsLong[0]) == "close", "ops long name close");
  check(std::string(kOpsNames[17]) == "em", "ops short name em");

  std::cout << "== parse_ll ==\n";
  check(parse_ll("  42") && *parse_ll("  42") == 42, "parse_ll trims spaces");
  check(parse_ll("-1") && *parse_ll("-1") == -1, "parse_ll negative");
  check(!parse_ll("NI"), "parse_ll NI fails");
  check(!parse_ll(""), "parse_ll empty fails");

  std::cout << "== parser (synthetic dump, comments tolerated) ==\n";
  {
    std::string dump =
      "protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re bi br ha uh gp em\n"
      "# skip me\n"
      "\n"
      "TCP       2304     22       0   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n"
      "PACKET    1536      0      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n";
    std::string path = "/tmp/protocols-selftest.table";
    Snapshot s;
    check(dump_to_file(path, dump), "writes dump");
    check(parse_protocols_file(path, s), "parses dump");
    std::remove(path.c_str());
    check(s.protos.size() == 2, "2 protocols parsed");
    if (s.protos.size() == 2) {
      check(s.protos[0].name == "TCP" && s.protos[0].size == 2304, "TCP size 2304");
      check(s.protos[0].sockets == 22 && s.protos[0].maxhdr == 320, "TCP socks=22 maxhdr=320");
      check(s.protos[0].slab && s.protos[0].press == "no", "TCP slab yes press no");
      check(s.protos[0].ops.size() == 18, "TCP 18 ops flags");
      check(s.protos[0].ops_yes() == 17, "TCP 17/18 ops (bi=n)");
      check(s.protos[0].family == "ipv4", "TCP family ipv4");
      check(s.protos[1].name == "PACKET" && s.protos[1].memory == -1, "PACKET memory -1");
      check(s.protos[1].press == "NI" && !s.protos[1].slab, "PACKET press NI no-slab");
      check(s.protos[1].ops_yes() == 0, "PACKET 0 ops");
      check(s.protos[1].family == "packet", "PACKET family packet");
    }
  }

  std::cout << "== real /proc (tolerant) ==\n";
  {
    Snapshot s;
    check(parse_protocols_file("/proc/net/protocols", s), "reads real /proc/net/protocols");
    check(!s.protos.empty(), "host has at least one protocol");
    bool has_tcp = false, sizes_ok = true, ops_ok = true;
    for (const auto& p : s.protos) {
      if (p.name == "TCP") has_tcp = true;
      if (p.size <= 0) sizes_ok = false;
      if (p.ops.size() > 18) ops_ok = false;
    }
    check(has_tcp, "host registers TCP");
    check(sizes_ok, "all obj_size > 0");
    check(ops_ok, "ops flags <= 18");
  }

  std::cout << "== demo summary ==\n";
  {
    Snapshot s;
    check(demo_load(s), "demo loads");
    check(s.protos.size() == 18, "demo 18 protocols");
    check(s.active() == 11, "demo 11 active");
    check(s.total_sockets() == 208, "demo sockets == 208");
    check(s.total_memory() == 24576, "demo memory 16384+8192");
    check(s.pressure_count() == 1, "demo 1 under pressure (TCP)");
    check(s.slab_count() == 14, "demo 14 slab-backed");
    auto fam = s.by_family();
    check(fam["ipv4"] == 6, "demo 6 ipv4");
    check(fam["ipv6"] == 6, "demo 6 ipv6");
    check(fam["unix"] == 2, "demo 2 unix");
    check(fam["netlink"] == 1 && fam["packet"] == 1, "demo netlink+packet");
    check(fam["xdp"] == 1 && fam["mctp"] == 1, "demo xdp+mctp");
    const Proto* tcp = s.find("TCP");
    check(tcp && tcp->sockets == 88 && tcp->has_pressure(), "demo TCP 88 press yes");
    check(tcp && tcp->ops_yes() == 17, "demo TCP 17 ops");
    const Proto* us = s.find("UNIX-STREAM");
    check(us && us->sockets == 48 && us->family == "unix", "demo UNIX-STREAM 48");
    // sort: sockets desc, so first should be TCP
    check(!s.protos.empty() && s.protos.front().name == "TCP", "demo sorted sockets desc");
  }

  std::cout << "== filters ==\n";
  {
    Snapshot s;
    check(demo_load(s), "demo for filters");
    Filters f; f.active = true;
    int n = 0; for (const auto& p : s.protos) if (passes(p, f)) ++n;
    check(n == 11, "demo --active == 11");
    f = Filters{}; f.family = "ipv6";
    n = 0; for (const auto& p : s.protos) if (passes(p, f)) ++n;
    check(n == 6, "demo --family ipv6 == 6");
    f = Filters{}; f.name = "UDP";
    n = 0; for (const auto& p : s.protos) if (passes(p, f)) ++n;
    check(n == 4, "demo --name UDP == 4 (UDP/UDP-Lite/UDPv6/UDPLITEv6)");
    f = Filters{}; f.press = true;
    n = 0; for (const auto& p : s.protos) if (passes(p, f)) ++n;
    check(n == 1, "demo --press == 1");
    f = Filters{}; f.slab = true; f.family = "unix";
    n = 0; for (const auto& p : s.protos) if (passes(p, f)) ++n;
    check(n == 2, "demo --slab --family unix == 2");
    f = Filters{}; f.active = true; f.family = "ipv4";
    n = 0; for (const auto& p : s.protos) if (passes(p, f)) ++n;
    check(n == 4, "demo active ipv4 == 4 (TCP/UDP/MPTCP/PING)");
  }

  std::cout << "== JSON validity ==\n";
  {
    Snapshot s;
    s.ts = 1787760000;
    check(demo_load(s), "demo for json");
    std::ostringstream os;
    render_json(os, s, true);
    std::string j = os.str();
    check(j.starts_with("{\n  \"summary\": {"), "json starts with quoted summary key");
    check(j.find("\"protocols\": [") != std::string::npos, "json has quoted protocols array");
    check(j.find("\"name\": \"TCP\"") != std::string::npos, "json TCP name quoted");
    check(j.find("\"family\": \"ipv4\"") != std::string::npos, "json family quoted");
    check(j.find("\"press\": \"yes\"") != std::string::npos, "json press quoted");
    check(j.find("\"source\": \"demo\"") != std::string::npos, "json source demo");
    check(std::count(j.begin(), j.end(), '{') == std::count(j.begin(), j.end(), '}'),
          "json braces balanced");
    check(j.rfind("}") == j.size() - 2, "json ends with closing brace");
    check(json_escape("a\"b") == "a\\\"b", "json_escape quotes");
  }

  std::cout << "\nRESULT: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void usage() {
  std::cout <<
    "Usage: ./protocols-watch [options]\n"
    "  Kernel socket-protocol table — /proc/net/protocols\n"
    "\n"
    "  --active             only protocols with sockets > 0\n"
    "  --family NAME        ipv4 | ipv6 | unix | netlink | packet | xdp | mctp | other\n"
    "  --name PREFIX        only names starting with PREFIX (e.g. UDP, TCP)\n"
    "  --press              only protocols currently under memory pressure\n"
    "  --slab               only slab-backed protocols\n"
    "  --top N              show only the first N rows (after sort by sockets)\n"
    "  --ops                print decoded proto_ops flags (cl|co|di|...)\n"
    "  --watch N            refresh every N seconds with socket-count deltas\n"
    "  --json               machine-readable JSON output\n"
    "  --demo               synthetic busy-host table (18 protocols)\n"
    "  --file PATH          parse a dump instead of /proc (tolerates # comments)\n"
    "  --no-color           disable ANSI colors (0 escapes in pipes)\n"
    "  --selftest           run self-tests\n"
    "  -h, --help           show this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next_val = [&](const char* flag) -> std::optional<std::string> {
      if (i + 1 < argc) { ++i; return std::string(argv[i]); }
      std::cerr << "Missing value for " << flag << "\n";
      return std::nullopt;
    };
    if (a == "-h" || a == "--help")  { usage(); return 0; }
    else if (a == "--selftest")      { return selftest(); }
    else if (a == "--no-color")      { f.color = false; disable_color(); }
    else if (a == "--json")          { f.json = true; }
    else if (a == "--demo")          { f.demo = true; }
    else if (a == "--active")        { f.active = true; }
    else if (a == "--press")         { f.press = true; }
    else if (a == "--slab")          { f.slab = true; }
    else if (a == "--ops")           { f.show_ops = true; }
    else if (a == "--family") {
      auto v = next_val("--family"); if (!v) return 2;
      f.family = *v;
    }
    else if (a == "--name") {
      auto v = next_val("--name"); if (!v) return 2;
      f.name = *v;
    }
    else if (a == "--top") {
      auto v = next_val("--top"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.top = static_cast<int>(*n); else { std::cerr << "Bad --top\n"; return 2; }
    }
    else if (a == "--watch") {
      auto v = next_val("--watch"); if (!v) return 2;
      if (auto n = parse_ll(*v)) f.watch = static_cast<int>(*n); else { std::cerr << "Bad --watch\n"; return 2; }
      if (f.watch <= 0) f.watch = 0;
    }
    else if (a == "--file") {
      auto v = next_val("--file"); if (!v) return 2;
      f.file = *v;
    }
    else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 2; }
  }

  auto load = [&](Snapshot& s) -> bool {
    if (f.demo) return demo_load(s);
    std::string path = f.file.empty() ? "/proc/net/protocols" : f.file;
    return load_snapshot(s, path);
  };

  if (f.watch > 0) {
    Snapshot prev, cur;
    load(prev);
    for (;;) {
      load(cur);
      cur.ts = now_secs();
      if (f.json) render_json(std::cout, cur, f.demo);
      else        render_snapshot(cur, f, true);
      render_delta(prev, cur, f);
      prev = std::move(cur);
      std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned>(f.watch)));
    }
  }

  Snapshot s;
  if (!load(s)) {
    std::cerr << "Cannot open " << (f.file.empty() ? "/proc/net/protocols" : f.file) << "\n";
    return 1;
  }
  s.ts = now_secs();
  if (f.json) render_json(std::cout, s, f.demo);
  else        render_snapshot(s, f, false);
  return 0;
}
