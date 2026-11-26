const std = @import("std");
const Translator = @import("translate_c").Translator;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Zig module.
    const mod = b.addModule("lora", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // C library: src/c.zig exports the functions declared in include/lora.h.
    const c_mod = b.createModule(.{
        .root_source_file = b.path("src/c.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "lora", .module = mod }},
    });
    const lib = b.addLibrary(.{ .name = "lora", .root_module = c_mod, .linkage = .static });
    lib.installHeader(b.path("include/lora.h"), "lora.h");
    b.installArtifact(lib);

    const version = std.SemanticVersion.parse(@import("build.zig.zon").version) catch unreachable;
    const shared = b.addLibrary(.{ .name = "lora", .root_module = c_mod, .linkage = .dynamic, .version = version });
    b.installArtifact(shared);

    // Tests.
    const test_step = b.step("test", "Run unit tests");

    const tests = b.addTest(.{ .root_module = mod });
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const c_tests = b.addTest(.{ .root_module = c_mod });
    test_step.dependOn(&b.addRunArtifact(c_tests).step);

    // ABI check: include/lora.h translated to Zig, compared with src/c.zig.
    const header: Translator = .init(b.dependency("translate_c", .{}), .{
        .c_source_file = b.path("include/lora.h"),
        .target = target,
        .optimize = optimize,
    });
    const abi_mod = b.createModule(.{
        .root_source_file = b.path("src/c_abi_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "lora", .module = mod }},
    });
    abi_mod.addImport("lora_h", header.mod);
    const abi_tests = b.addTest(.{ .root_module = abi_mod });
    test_step.dependOn(&b.addRunArtifact(abi_tests).step);

    // C program against include/lora.h and the static library.
    const c_test_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    c_test_mod.addCSourceFile(.{ .file = b.path("tests/c/test_lora.c"), .flags = &.{ "-std=c99", "-Wall", "-Wextra", "-Werror" } });
    c_test_mod.addIncludePath(b.path("include"));
    c_test_mod.linkLibrary(lib);
    const c_test_exe = b.addExecutable(.{ .name = "test_lora_c", .root_module = c_test_mod });
    test_step.dependOn(&b.addRunArtifact(c_test_exe).step);
}
