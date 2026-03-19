const std = @import("std");
const Allocator = std.mem.Allocator;

const State = struct {
    allocator: Allocator,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stdin_buffer: []u8,
    stdout_buffer: []u8,
    mode: Mode,
    user_name: []u8,
    password: []u8,

    pub fn init(allocator: Allocator) !State {
        const stdout_buffer = try allocator.alloc(u8, 512);
        var w = std.fs.File.stdout().writer(stdout_buffer);
        const writer = &w.interface;

        const stdin_buffer = try allocator.alloc(u8, 512);
        var r = std.fs.File.stdin().reader(stdin_buffer);
        const reader = &r.interface;
        const state: State = .{
            .allocator = allocator,
            .stdin_buffer = stdin_buffer,
            .stdout_buffer = stdout_buffer,
            .stdin = reader,
            .stdout = writer,
            .user_name = undefined,
            .password = undefined,
            .mode = Mode.uninnited,
        };
        return state;
    }

    pub fn deinit(s: State) !void {
        s.stdout.flush() catch |err| {
            std.debug.print("failed to flush stdout:{any}\n", .{err});
        };
        s.allocator.free(s.stdout_buffer);
        s.allocator.free(s.stdin_buffer);

        s.allocator.free(s.user_name);
        s.allocator.free(s.password);
    }
};

const Mode = enum {
    uninnited,
    setup,
    ready,
};

fn parse_arguments(s: *State) !void {
    const args = try std.process.argsAlloc(s.allocator);
    defer s.allocator.free(args);

    for (args, 0..) |arg, i| {
        try s.stdout.print("{d}. {any}\n", .{ i, arg });
    }
    try s.stdout.flush();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer if (gpa.deinit() == .leak) @panic("leaked");
    const allocator = gpa.allocator();
    var state: State = try .init(allocator);
    try parse_arguments(&state);
    try state.deinit();
}
