#!/usr/bin/env python3
import sys
from pathlib import Path


def fail(message):
    print("ERROR: " + message, file=sys.stderr)
    sys.exit(1)


def find_function_end(lines, start):
    depth = 0
    opened = False
    for index in range(start, len(lines)):
        line = lines[index]
        if "{" in line:
            opened = True
        depth += line.count("{")
        depth -= line.count("}")
        if opened and depth == 0:
            return index
    return None


def find_function(lines, signature):
    for index, line in enumerate(lines):
        if signature in line:
            end = find_function_end(lines, index)
            if end is None:
                fail("Cannot find end of function: " + signature)
            return index, end
    fail("Function not found: " + signature)


def ensure_existing_hook(kernel_dir, relative_path, signature, marker):
    path = kernel_dir / relative_path
    if not path.is_file():
        fail("Source file not found: " + str(path))
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start, end = find_function(lines, signature)
    if marker not in "".join(lines[start:end + 1]):
        fail("Required existing hook missing in " + relative_path + ": " + marker)
    print("Verified existing hook: " + relative_path + " -> " + marker)


def inject_hook(kernel_dir, relative_path, signature, anchor, hook_code, marker, mode="after"):
    path = kernel_dir / relative_path
    if not path.is_file():
        fail("Source file not found: " + str(path))
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start, end = find_function(lines, signature)
    if marker in "".join(lines[start:end + 1]):
        print("Already patched: " + relative_path + " -> " + marker)
        return
    anchor_index = None
    for index in range(start, end + 1):
        if anchor in lines[index]:
            anchor_index = index
            break
    if anchor_index is None:
        fail("Anchor not found in " + relative_path + ": " + anchor)
    block = chr(10) + hook_code.strip() + chr(10)
    if mode == "before":
        lines.insert(anchor_index, block)
    elif mode == "after":
        lines.insert(anchor_index + 1, block)
    else:
        fail("Unknown insertion mode: " + mode)
    path.write_text("".join(lines), encoding="utf-8")
    print("Injected: " + relative_path + " -> " + marker)


def main():
    if len(sys.argv) != 2:
        fail("Usage: python3 scripts/inject_ksu_hooks.py kernel")
    kernel_dir = Path(sys.argv[1]).resolve()
    if not (kernel_dir / "Makefile").is_file():
        fail("Not a kernel source directory: " + str(kernel_dir))

    ensure_existing_hook(kernel_dir, "fs/exec.c", "do_execveat_common(", "ksu_handle_execveat")
    ensure_existing_hook(kernel_dir, "fs/open.c", "faccessat(", "ksu_handle_faccessat")
    ensure_existing_hook(kernel_dir, "fs/read_write.c", "vfs_read(", "ksu_handle_vfs_read")
    ensure_existing_hook(kernel_dir, "fs/stat.c", "vfs_statx(", "ksu_handle_stat")

    reboot_declaration = """#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(
    int magic1,
    int magic2,
    unsigned int cmd,
    void __user **arg
);
#endif"""

    reboot_hook = """#ifdef CONFIG_KSU
    {
        int ksu_ret = ksu_handle_sys_reboot(
            magic1,
            magic2,
            cmd,
            (void __user **)&arg
        );
        if (ksu_ret)
            return ksu_ret;
    }
#endif"""

    input_hook = """#ifdef CONFIG_KSU
    extern int ksu_handle_input_handle_event(
        unsigned int *type,
        unsigned int *code,
        int *value
    );
    ksu_handle_input_handle_event(&type, &code, &value);
#endif"""

    inject_hook(kernel_dir, "kernel/reboot.c", "SYSCALL_DEFINE4(reboot", "SYSCALL_DEFINE4(reboot", reboot_declaration, "ksu_handle_sys_reboot", "before")
    inject_hook(kernel_dir, "kernel/reboot.c", "SYSCALL_DEFINE4(reboot", "int ret = 0;", reboot_hook, "int ksu_ret = ksu_handle_sys_reboot", "after")
    inject_hook(kernel_dir, "drivers/input/input.c", "input_handle_event(", "input_get_disposition", input_hook, "ksu_handle_input_handle_event", "after")

    print("KernelSU manual-hook verification and patch completed successfully.")


if __name__ == "__main__":
    main()
