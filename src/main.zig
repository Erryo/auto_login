const std = @import("std");
const Allocator = std.mem.Allocator;
const Default_Delay_s = 30;

const State = struct {
    allocator: Allocator,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stdin_buffer: []u8,
    stdout_buffer: []u8,
    mode: Mode,
    user_name: []u8,
    password: []u8,
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
            .mode = Mode.uninnited,
            .delay_s = Default_Delay_s,
        };
        return state;
    }

    pub fn deinit(s: *State) !void {
        try s.stdout.print("aae\n", .{});
        s.stdout.flush() catch |err| {
            std.debug.print("failed to flush stdout:{any}\n", .{err});
        };

        s.allocator.free(s.stdout_buffer);
        s.allocator.free(s.stdin_buffer);

        if (s.mode == .ready) {
            s.allocator.free(s.user_name);
            s.allocator.free(s.password);
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
        return;
    }

    for (args, 0..) |arg, i| {
        try s.stdout.print("{d}. {s}\n", .{ i, arg });
    }
    try s.stdout.flush();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer if (gpa.deinit() == .leak) @panic("leaked");
    const allocator = gpa.allocator();

    const stdout_buffer = try allocator.alloc(u8, 512);
    var w = std.fs.File.stdout().writer(stdout_buffer);
    const writer = &w.interface;

    const stdin_buffer = try allocator.alloc(u8, 512);
    var r = std.fs.File.stdin().reader(stdin_buffer);
    const reader = &r.interface;

    var state: State = try .init(allocator);
    state.stdout = writer;
    state.stdin = reader;
    state.stdin_buffer = stdin_buffer;
    state.stdout_buffer = stdout_buffer;

    // PARSE

    try parse_arguments(&state);
    try state.deinit();
}
