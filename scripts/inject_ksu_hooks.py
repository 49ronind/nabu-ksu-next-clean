#!/usr/bin/env python3

import sys
from pathlib import Path


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def find_function_end(lines, start_index):
    depth = 0
    opened = False

    for index in range(start_index, len(lines)):
        line = lines[index]

        if "{" in line:
            opened = True

        depth += line.count("{")
        depth -= line.count("}")

        if opened and depth == 0:
            return index

    return None


def inject_hook(kernel_dir, relative_path, function_signature,
                anchor, hook_code, unique_marker, mode="after"):
    path = kernel_dir / relative_path

    if not path.is_file():
        fail(f"Source file not found: {path}")

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    function_start = None
    for index, line in enumerate(lines):
        if function_signature in line:
            function_start = index
            break

    if function_start is None:
        fail(
            f"Function signature not found in {relative_path}: "
            f"{function_signature}"
        )

    function_end = find_function_end(lines, function_start)

    if function_end is None:
        fail(
            f"Could not locate end of function in {relative_path}: "
            f"{function_signature}"
        )

    function_text = "".join(lines[function_start:function_end + 1])

    if unique_marker in function_text:
        print(f"Already patched: {relative_path} -> {unique_marker}")
        return

    anchor_index = None
    for index in range(function_start, function_end + 1):
        if anchor in lines[index]:
            anchor_index = index
            break

    if anchor_index is None:
        fail(
            f"Anchor not found inside {relative_path}, "
            f"{function_signature}: {anchor}"
        )

    block = "
" + hook_code.rstrip() + "
"

    if mode == "before":
        lines.insert(anchor_index, block)
    elif mode == "after":
        lines.insert(anchor_index + 1, block)
    else:
        fail(f"Unknown injection mode: {mode}")

    path.write_text("".join(lines), encoding="utf-8")
    print(f"Injected: {relative_path} -> {unique_marker}")


def main():
    if len(sys.argv) != 2:
        fail("Usage: python3 scripts/inject_ksu_hooks.py kernel")

    kernel_dir = Path(sys.argv[1]).resolve()

    if not (kernel_dir / "Makefile").is_file():
        fail(f"Not a kernel source directory: {kernel_dir}")

    exec_hook = r"""
#ifdef CONFIG_KSU
    extern int ksu_handle_execveat(
        int *fd,
        struct filename **filename_ptr,
        void *argv,
        void *envp,
        int *flags
    );
    ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
#endif
"""

    open_hook = r"""
#ifdef CONFIG_KSU
    extern int ksu_handle_faccessat(
        int *dfd,
        const char __user **filename_user,
        int *mode,
        int *flags
    );
    ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif
"""

    read_hook = r"""
#ifdef CONFIG_KSU
    ksu_handle_vfs_read(&file, &buf, &count, &pos);
#endif
"""

    stat_hook = r"""
#ifdef CONFIG_KSU
    extern int ksu_handle_stat(
        int *dfd,
        const char __user **filename_user,
        int *flags
    );
    ksu_handle_stat(&dfd, &filename, &flags);
#endif
"""

    reboot_declaration = r"""
#ifdef CONFIG_KSU
extern int ksu_handle_sys_reboot(
    int magic1,
    int magic2,
    unsigned int cmd,
    void __user **arg
);
#endif
"""

    reboot_hook = r"""
#ifdef CONFIG_KSU
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
#endif
"""

    input_hook = r"""
#ifdef CONFIG_KSU
    extern int ksu_handle_input_handle_event(
        unsigned int *type,
        unsigned int *code,
        int *value
    );
    ksu_handle_input_handle_event(&type, &code, &value);
#endif
"""

    inject_hook(
        kernel_dir,
        "fs/exec.c",
        "do_execveat_common(",
        "int retval;",
        exec_hook,
        "ksu_handle_execveat",
        "after"
    )

    inject_hook(
        kernel_dir,
        "fs/open.c",
        "faccessat(",
        "unsigned int lookup_flags",
        open_hook,
        "ksu_handle_faccessat",
        "after"
    )

    inject_hook(
        kernel_dir,
        "fs/read_write.c",
        "vfs_read(",
        "if (!(file->f_mode & FMODE_CAN_READ))",
        read_hook,
        "ksu_handle_vfs_read",
        "before"
    )

    inject_hook(
        kernel_dir,
        "fs/stat.c",
        "vfs_statx(",
        "struct path path;",
        stat_hook,
        "ksu_handle_stat",
        "after"
    )

    inject_hook(
        kernel_dir,
        "kernel/reboot.c",
        "SYSCALL_DEFINE4(reboot",
        "SYSCALL_DEFINE4(reboot",
        reboot_declaration,
        "ksu_handle_sys_reboot",
        "before"
    )

    inject_hook(
        kernel_dir,
        "kernel/reboot.c",
        "SYSCALL_DEFINE4(reboot",
        "int ret = 0;",
        reboot_hook,
        "int ksu_ret = ksu_handle_sys_reboot",
        "after"
    )

    inject_hook(
        kernel_dir,
        "drivers/input/input.c",
        "input_handle_event(",
        "input_get_disposition",
        input_hook,
        "ksu_handle_input_handle_event",
        "after"
    )

    print("KernelSU manual-hook patch completed successfully.")


if __name__ == "__main__":
    main()
