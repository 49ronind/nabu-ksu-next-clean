#!/usr/bin/env python3
import sys
from pathlib import Path


def fail(message):
    print("ERROR: " + message, file=sys.stderr)
    sys.exit(1)


def function_range(lines, declaration):
    for start, line in enumerate(lines):
        if declaration not in line:
            continue
        depth = 0
        opened = False
        for end in range(start, len(lines)):
            current = lines[end]
            if "{" in current:
                opened = True
            depth += current.count("{")
            depth -= current.count("}")
            if opened and depth == 0:
                return start, end
    fail("Function definition not found: " + declaration)


def verify_hook(kernel_dir, relative_path, declaration, marker):
    path = kernel_dir / relative_path
    if not path.is_file():
        fail("Source file not found: " + str(path))
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start, end = function_range(lines, declaration)
    if marker not in "".join(lines[start:end + 1]):
        fail("Required existing hook missing in " + relative_path + ": " + marker)
    print("Verified existing hook: " + relative_path + " -> " + marker)


def inject_hook(kernel_dir, relative_path, declaration, anchor, code, marker, before=False):
    path = kernel_dir / relative_path
    if not path.is_file():
        fail("Source file not found: " + str(path))
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start, end = function_range(lines, declaration)
    if marker in "".join(lines[start:end + 1]):
        print("Already patched: " + relative_path + " -> " + marker)
        return
    for index in range(start, end + 1):
        if anchor in lines[index]:
            block = chr(10) + code.strip() + chr(10)
            lines.insert(index if before else index + 1, block)
            path.write_text("".join(lines), encoding="utf-8")
            print("Injected: " + relative_path + " -> " + marker)
            return
    fail("Anchor not found in " + relative_path + ": " + anchor)


def main():
    if len(sys.argv) != 2:
        fail("Usage: python3 scripts/inject_ksu_hooks.py kernel")
    kernel_dir = Path(sys.argv[1]).resolve()
    if not (kernel_dir / "Makefile").is_file():
        fail("Not a kernel source directory: " + str(kernel_dir))

    verify_hook(kernel_dir, "fs/exec.c", "do_execveat_common(", "ksu_handle_execveat")
    verify_hook(kernel_dir, "fs/open.c", "faccessat(", "ksu_handle_faccessat")
    verify_hook(kernel_dir, "fs/read_write.c", "ssize_t vfs_read(", "ksu_handle_vfs_read")
    verify_hook(kernel_dir, "fs/stat.c", "vfs_statx(", "ksu_handle_stat")

    reboot_declaration = """#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(int magic1, int magic2,
                                 unsigned int cmd, void __user **arg);
#endif"""

    reboot_hook = """#ifdef CONFIG_KSU
    {
        int ksu_ret = ksu_handle_sys_reboot(
            magic1, magic2, cmd, (void __user **)&arg);
        if (ksu_ret)
            return ksu_ret;
    }
#endif"""

    input_hook = """#ifdef CONFIG_KSU
    extern int ksu_handle_input_handle_event(
        unsigned int *type, unsigned int *code, int *value);
    ksu_handle_input_handle_event(&type, &code, &value);
#endif"""

    inject_hook(kernel_dir, "kernel/reboot.c", "SYSCALL_DEFINE4(reboot",
                "SYSCALL_DEFINE4(reboot", reboot_declaration,
                "ksu_handle_sys_reboot", before=True)
    inject_hook(kernel_dir, "kernel/reboot.c", "SYSCALL_DEFINE4(reboot",
                "int ret = 0;", reboot_hook,
                "int ksu_ret = ksu_handle_sys_reboot")
    inject_hook(kernel_dir, "drivers/input/input.c", "input_handle_event(",
                "input_get_disposition", input_hook,
                "ksu_handle_input_handle_event")

    print("KernelSU manual-hook verification and patch completed successfully.")


if __name__ == "__main__":
    main()
