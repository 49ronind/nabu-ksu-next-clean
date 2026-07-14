#!/usr/bin/env python3
import sys
from pathlib import Path

BACKPORT = """static int can_umount(const struct path *path, int flags)
{
	struct mount *mnt = real_mount(path->mnt);

	if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
		return -EINVAL;
	if (!may_mount())
		return -EPERM;
	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;
	if (!check_mnt(mnt))
		return -EINVAL;
	if (mnt->mnt.mnt_flags & MNT_LOCKED)
		return -EINVAL;
	if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int path_umount(struct path *path, int flags)
{
	struct mount *mnt = real_mount(path->mnt);
	int ret;

	ret = can_umount(path, flags);
	if (!ret)
		ret = do_umount(mnt, flags);

	/* we mustn't call path_put() as that would clear mnt_expiry_mark */
	dput(path->dentry);
	mntput_no_expire(mnt);
	return ret;
}

"""

ANCHOR = """/*
 * Now umount can handle mount points as well as block devices."""


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: backport_path_umount.py <kernel_dir>')

    kernel_dir = Path(sys.argv[1])
    namespace = kernel_dir / 'fs' / 'namespace.c'

    if not namespace.exists():
        raise SystemExit(f'missing file: {namespace}')

    s = namespace.read_text()

    if 'int path_umount(struct path *path, int flags)' in s:
        print('path_umount already present in fs/namespace.c')
        return

    idx = s.find(ANCHOR)
    if idx == -1:
        raise SystemExit('Insertion point not found in fs/namespace.c')

    s = s[:idx] + BACKPORT + s[idx:]
    namespace.write_text(s)
    print('Inserted path_umount backport into fs/namespace.c')


if __name__ == '__main__':
    main()
