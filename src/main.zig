const std = @import("std");
const Allocator = std.mem.Allocator;
const Default_Delay_s = 30;
const Max_Attempts = 3;
const Default_Path = "data.txt";
const Default_Path_Encrypted = "data.enc";
const Sleep_notConnected_nano = std.time.ns_per_s * 30;
const Sleep_noInternet_nano = std.time.ns_per_s * 10;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
const Auth_Path = "/api/captiveportal/access/logon/0/";
const headers = "Content-Type: application/x-www-form-urlencoded";
const Server_IP = "10.80.0.1";
const Server_Port = 8000;

const Ping_Addr_Port = 80;
const Ping_Addr = "34.107.221.82";
const random = std.crypto.random;
const net = std.net;
const Secret_Key: [32]u8 = [32]u8{
    0x4b, 0x65, 0x79, 0x21, 0x54, 0x68, 0x69, 0x73,
    0x49, 0x73, 0x4d, 0x79, 0x53, 0x65, 0x63, 0x72,
    0x65, 0x74, 0x4b, 0x65, 0x79, 0x46, 0x6f, 0x72,
    0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x47, 0x43,
};
const alphabet_chars = std.base64.url_safe_alphabet_chars;
const ParseError = error{ InvalidNonce, InvalidLine };
const ChildError = error{ Unknown, NoConnection, Failed };

const Help_Message =
    \\ -h,--help -> print the help message
    \\ -s,--setup -> setup
    \\ -e, --encrypt -> encrypt the data file
    \\ no arg -> start monitoring 
;
const State = struct {
    allocator: Allocator,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stdin_buffer: []u8,
    stdout_buffer: []u8,
    mode: Mode,
    user_name: []u8,
    password: []u8,
    network_name: []u8,
    encrypt: bool = false,
    delay_s: u32,

    pub fn init(allocator: Allocator) !State {
        const state: State = .{
            .allocator = allocator,
            .stdin_buffer = undefined,
            .stdout_buffer = undefined,
            .stdin = undefined,
            .stdout = undefined,
            .user_name = undefined,
            .password = undefined,
            .network_name = undefined,
            .mode = Mode.uninnited,
            .delay_s = Default_Delay_s,
        };
        return state;
    }

    pub fn deinit(s: *State) !void {
        std.debug.print("deinit: s.mode: {s}\n", .{@tagName(s.mode)});
        if (s.mode == .ready) {
            s.allocator.free(s.user_name);
            s.allocator.free(s.password);
            s.allocator.free(s.network_name);
        }
        s.mode = .uninnited;
    }
};

const Mode = enum {
    uninnited,
    setup,
    readin,
    ready,
};

fn parse_arguments(s: *State) !void {
    const args = try std.process.argsAlloc(s.allocator);
    defer std.process.argsFree(s.allocator, args);

    if (args.len == 1) {
        s.mode = .readin;
        try read_in(s);
        return;
    }

    var setup_b: bool = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try print_help(s);
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--setup")) {
            std.debug.print("setting up\n", .{});
            setup_b = true;
        } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--encrypt")) {
            std.debug.print("encrypting file\n", .{});
            s.encrypt = true;
        } else {}
    }

    if (setup_b) {
        try setup(s);
    } else {
        try read_in(s);
    }
    try s.stdout.flush();
}

fn setup(s: *State) !void {
    s.mode = .readin;
    try s.stdout.print("Setup Menu \n Please entre your login data\n\n", .{});
    try s.stdout.print("Network Name: ", .{});
    try s.stdout.flush();
    var n_attempts: u8 = 0;

    var network_line: []u8 = undefined;
    while (n_attempts < Max_Attempts) : (n_attempts += 1) {
        const line = s.stdin.takeDelimiterExclusive('\n') catch |err| {
            try s.stdout.print("\nthe program failed to process your input because of an error:{s}\nPlease try again!\n", .{@errorName(err)});
            continue;
        };
        network_line = try s.allocator.dupe(u8, line);
        break;
    }
    try s.stdout.print("User Name: ", .{});
    try s.stdout.flush();

    var user_name_line: []u8 = undefined;
    while (n_attempts < Max_Attempts) : (n_attempts += 1) {
        const line = s.stdin.takeDelimiterExclusive('\n') catch |err| {
            try s.stdout.print("\nthe program failed to process your input because of an error:{s}\nPlease try again!\n", .{@errorName(err)});
            continue;
        };
        user_name_line = try s.allocator.dupe(u8, line);
        break;
    }

    try s.stdout.print("Password: ", .{});
    try s.stdout.flush();
    var password_line: []u8 = undefined;
    while (n_attempts < Max_Attempts) : (n_attempts += 1) {
        const line = s.stdin.takeDelimiterExclusive('\n') catch |err| {
            try s.stdout.print("\nthe program failed to process your input because of an error:{s}\nPlease try again!\n", .{@errorName(err)});
            continue;
        };
        password_line = try s.allocator.dupe(u8, line);
        break;
    }

    s.password = password_line;
    s.user_name = user_name_line;
    s.network_name = network_line;

    if (s.encrypt == true) try write_encrypt(s) else try write_plaintext(s);

    try s.stdout.flush();
    s.mode = .ready;
}

fn read_in(s: *State) !void {
    s.mode = .readin;
    if (s.encrypt) {
        read_encrypt(s) catch |err| {
            if (err == std.fs.File.OpenError.FileNotFound) {
                try read_plaintext(s);
            } else {
                return err;
            }
        };
    } else {
        read_plaintext(s) catch |err| {
            if (err == std.fs.File.OpenError.FileNotFound) {
                try read_encrypt(s);
            } else {
                return err;
            }
        };
    }
}

fn read_plaintext(s: *State) !void {
    const file = try std.fs.cwd().openFile(Default_Path, .{ .mode = .read_only });
    defer file.close();
    var buffer: [512]u8 = std.mem.zeroes([512]u8);
    var r = file.reader(&buffer);
    const reader = &r.interface;

    const network_slice = try reader.takeDelimiterExclusive('\n');
    s.network_name = try s.allocator.dupe(u8, network_slice);

    const username_slice = try reader.takeDelimiterExclusive('\n');
    s.user_name = try s.allocator.dupe(u8, username_slice);

    const password_slice = try reader.takeDelimiterExclusive('\n');
    s.password = try s.allocator.dupe(u8, password_slice);

    std.debug.print("...........\n", .{});
    std.debug.print("nework:{s}\n", .{s.network_name});
    std.debug.print("user_name:{s}\n", .{s.user_name});
    std.debug.print("password:{s}\n", .{s.password});
    std.debug.print("+++++++++++++++++++++++++++\n", .{});
    s.mode = .ready;
}

fn read_encrypt(s: *State) !void {
    const file = try std.fs.cwd().openFile(Default_Path_Encrypted, .{ .mode = .read_only });
    defer file.close();

    var buffer: [512]u8 = std.mem.zeroes([512]u8);
    var r = file.reader(&buffer);
    const reader = &r.interface;

    const network_slice = try reader.takeDelimiterExclusive('\n');
    //  std.debug.print("network_slice: {s}\n", .{network_slice});
    s.network_name = try process_encrypted_line(network_slice, s);

    const username_slice = try reader.takeDelimiterExclusive('\n');
    //   std.debug.print("username_slice: {s}\n", .{username_slice});
    s.user_name = try process_encrypted_line(username_slice, s);

    const password_slice = try reader.takeDelimiterExclusive('\n');
    //    std.debug.print("password_slice: {s}\n", .{password_slice});
    s.password = try process_encrypted_line(password_slice, s);

    s.mode = .ready;
    //
    std.debug.print("...........\n", .{});
    std.debug.print("nework:{s}\n", .{s.network_name});
    std.debug.print("user_name:{s}\n", .{s.user_name});
    std.debug.print("password:{s}\n", .{s.password});
    std.debug.print("+++++++++++++++++++++++++++\n", .{});
}
fn process_encrypted_line(line: []u8, s: *State) ![]u8 {
    var it = std.mem.splitAny(u8, line, ":");
    var idx: u8 = 0;
    var nonce_encoded: ?[]const u8 = null;
    var data_encoded: ?[]const u8 = null;
    while (it.next()) |part| {
        defer idx += 1;
        if (idx == 0) {
            nonce_encoded = part;
        } else {
            data_encoded = part;
        }
    }
    if (data_encoded == null or nonce_encoded == null) return ParseError.InvalidLine;

    const nonce_slice = try base64_decode(nonce_encoded.?, s.allocator);
    defer s.allocator.free(nonce_slice);
    if (nonce_slice.len != 12) return ParseError.InvalidNonce;
    const nonce = nonce_slice[0..12].*;

    const encrypted_data = try base64_decode(data_encoded.?, s.allocator);
    defer s.allocator.free(encrypted_data);

    const plain_data: []u8 = try s.allocator.dupe(u8, encrypted_data);
    ChaCha20.xor(plain_data, encrypted_data, 0, Secret_Key, nonce);

    return plain_data;
}

pub fn write_encrypt(s: *State) !void {
    const file = try std.fs.cwd().createFile(Default_Path_Encrypted, .{ .read = true, .truncate = true });
    defer file.close();

    var buffer = std.mem.zeroes([512]u8);
    var w = file.writer(&buffer);
    const writer = &w.interface;
    {
        var nonce: [12]u8 = undefined;
        random.bytes(&nonce);

        const encrypted_data = try s.allocator.dupe(u8, s.network_name);
        defer s.allocator.free(encrypted_data);

        ChaCha20.xor(encrypted_data, s.network_name, 0, Secret_Key, nonce);

        const encoded_data = try base64_encode(encrypted_data, s.allocator);
        defer s.allocator.free(encoded_data);
        const encoded_nonce = try base64_encode(&nonce, s.allocator);
        defer s.allocator.free(encoded_nonce);
        try writer.print("{s}:{s}\n", .{ encoded_nonce, encoded_data });
    }

    {
        var nonce: [12]u8 = undefined;
        random.bytes(&nonce);

        const encrypted_data = try s.allocator.dupe(u8, s.user_name);
        defer s.allocator.free(encrypted_data);

        ChaCha20.xor(encrypted_data, s.user_name, 0, Secret_Key, nonce);

        const encoded_data = try base64_encode(encrypted_data, s.allocator);
        defer s.allocator.free(encoded_data);
        const encoded_nonce = try base64_encode(&nonce, s.allocator);
        defer s.allocator.free(encoded_nonce);
        try writer.print("{s}:{s}\n", .{ encoded_nonce, encoded_data });
    }
    {
        var nonce: [12]u8 = undefined;
        random.bytes(&nonce);

        const encrypted_data = try s.allocator.dupe(u8, s.password);
        defer s.allocator.free(encrypted_data);

        ChaCha20.xor(encrypted_data, s.password, 0, Secret_Key, nonce);

        const encoded_data = try base64_encode(encrypted_data, s.allocator);
        defer s.allocator.free(encoded_data);
        const encoded_nonce = try base64_encode(&nonce, s.allocator);
        defer s.allocator.free(encoded_nonce);
        try writer.print("{s}:{s}\n", .{ encoded_nonce, encoded_data });
    }
    try writer.flush();
}

pub fn write_plaintext(s: *State) !void {
    const file = try std.fs.cwd().createFile(Default_Path, .{ .read = true, .truncate = true });
    defer file.close();
    var buffer = std.mem.zeroes([512]u8);
    var w = file.writer(&buffer);
    const writer = &w.interface;
    try writer.print("{s}\n{s}\n{s}\n\n", .{ s.network_name, s.user_name, s.password });
    try writer.flush();
}

fn print_help(s: *State) !void {
    try s.stdout.print("{s}\n\n", .{Help_Message});
}

pub fn base64_encode(input: []const u8, allocator: Allocator) ![]const u8 {
    var encoder = std.base64.Base64Encoder.init(alphabet_chars, null);

    const size = encoder.calcSize(input.len);

    const buf = try allocator.alloc(u8, size);
    const result = encoder.encode(buf, input);

    return result;
}

pub fn base64_decode(input: []const u8, allocator: Allocator) ![]const u8 {
    var decoder = std.base64.Base64Decoder.init(alphabet_chars, null);

    const size = try decoder.calcSizeForSlice(input);
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    try decoder.decode(buffer, input);
    return buffer;
}

fn get_ssid(s: *State) ![]const u8 {
    return switch (@import("builtin").os.tag) {
        .linux => get_ssid_linux(s),
        .windows => get_ssid_windows(s),
        else => error.UnsupportedPlatform,
    };
}

fn get_ssid_linux(s: *State) ![]const u8 {
    const result = try std.process.Child.run(.{
        .allocator = s.allocator,
        .argv = &.{ "iwgetid", "-r" },
    });
    defer s.allocator.free(result.stderr);
    defer s.allocator.free(result.stdout);

    if (result.term != .Exited or result.term.Exited != 0) return ChildError.Failed;

    const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
    if (trimmed.len == 0) return ChildError.NoConnection;

    return try s.allocator.dupe(u8, trimmed);
}
fn get_ssid_windows(s: *State) ![]const u8 {
    const result = try std.process.Child.run(.{
        .allocator = s.allocator,
        .argv = &.{ "netsh", "wlan", "show", "interfaces" },
    });
    defer s.allocator.free(result.stderr);
    defer s.allocator.free(result.stdout);

    if (result.term != .Exited or result.term.Exited != 0) return ChildError.Failed;

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
        // Match "    SSID                   : MyNetwork"
        // but NOT "BSSID" lines
        if (std.mem.startsWith(u8, trimmed, "SSID") and
            !std.mem.startsWith(u8, trimmed, "BSSID"))
        {
            const colon = std.mem.indexOf(u8, trimmed, ":") orelse continue;
            const ssid = std.mem.trim(u8, trimmed[colon + 1 ..], &std.ascii.whitespace);
            if (ssid.len == 0) continue;
            return try s.allocator.dupe(u8, ssid);
        }
    }
    return ChildError.NoConnection;
}

fn connected_to_target(s: *State) !bool {
    const ssid = get_ssid(s) catch |err| {
        if (err == ChildError.NoConnection or err == ChildError.Failed) return false else return err;
    };
    defer s.allocator.free(ssid);
    //    try s.stdout.print("SSID:{s}\n", .{ssid});
    return std.mem.eql(u8, s.network_name, ssid);
}

fn check_internet(addr: net.Address) !bool {
    _ = net.tcpConnectToAddress(addr) catch |err| {
        if (err == net.TcpConnectToAddressError.NetworkUnreachable) return false else return err;
    };
    return true;
}

fn send_connect(request: []const u8, addr: net.Address) !void {
    const stream = try net.tcpConnectToAddress(addr);
    defer stream.close();

    try stream.writeAll(request);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer if (gpa.deinit() == .leak) @panic("leaked");
    const allocator = gpa.allocator();

    const stdout_buffer = try allocator.alloc(u8, 512);
    defer allocator.free(stdout_buffer);
    var w = std.fs.File.stdout().writer(stdout_buffer);
    const writer = &w.interface;

    const stdin_buffer = try allocator.alloc(u8, 512);
    defer allocator.free(stdin_buffer);
    var r = std.fs.File.stdin().reader(stdin_buffer);
    const reader = &r.interface;

    var state: State = try .init(allocator);
    defer state.deinit() catch |err| @panic(@errorName(err));
    state.stdout = writer;
    state.stdin = reader;
    state.stdin_buffer = stdin_buffer;
    state.stdout_buffer = stdout_buffer;

    defer state.stdout.flush() catch |err| {
        std.debug.print("failed to flush stdout:{any}\n", .{err});
    };
    try parse_arguments(&state);

    const addr: net.Address = try .parseIp4(Ping_Addr, Ping_Addr_Port);
    const server_addr: net.Address = try .parseIp4(Server_IP, Server_Port);

    const body = try std.fmt.allocPrint(state.allocator, "user={s}&password={s}", .{ state.user_name, state.password });
    defer state.allocator.free(body);

    const request = try std.fmt.allocPrint(
        allocator,
        "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}",
        .{ Auth_Path, Server_IP, Server_Port, headers, body.len, body },
    );
    defer allocator.free(request);
    // PARSE

    while (true) {
        const connected: bool = try connected_to_target(&state);
        if (!connected) {
            std.debug.print("no wlan", .{});
            std.Thread.sleep(Sleep_notConnected_nano);
            continue;
        }
        const internet: bool = try check_internet(addr);
        if (internet) {
            std.debug.print("got internet\n", .{});
            std.Thread.sleep(Sleep_noInternet_nano);
            continue;
        }
        std.debug.print("no  internet connection\n", .{});
        try send_connect(request, server_addr);
    }
}
