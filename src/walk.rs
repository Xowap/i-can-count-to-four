//! Whole-disk traversal.
//!
//! Policy, deliberately dumb and name-free: walk everything, follow nothing,
//! and only refuse to descend into *pseudo* filesystems (the kernel's virtual
//! filesystems such as `/proc`, `/sys`, `/dev`). We discover those from the
//! kernel's own mount table instead of hard-coding directory names, so this
//! keeps working regardless of where the distro mounts them.

use std::collections::HashSet;
use std::path::PathBuf;

/// Kernel / pseudo filesystem types that do not hold ordinary files.
const PSEUDO_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "securityfs",
    "selinuxfs",
    "smackfs",
    "debugfs",
    "tracefs",
    "configfs",
    "bpf",
    "cgroup",
    "cgroup2",
    "pstore",
    "mqueue",
    "hugetlbfs",
    "fusectl",
    "autofs",
    "rpc_pipefs",
    "nsfs",
    "binfmt_misc",
    "efivarfs",
    "ramfs",
];

/// Mount points whose filesystem is a pseudo filesystem; these directories are
/// pruned during the walk.
pub fn pseudo_mount_points() -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    let data = match std::fs::read_to_string("/proc/self/mounts") {
        Ok(d) => d,
        Err(_) => return set,
    };

    for line in data.lines() {
        let mut fields = line.split(' ');
        let _device = fields.next();
        let mount_point = match fields.next() {
            Some(m) => m,
            None => continue,
        };
        let fstype = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        if PSEUDO_FS.contains(&fstype) {
            set.insert(PathBuf::from(unescape_mount(mount_point)));
        }
    }
    set
}

/// The kernel escapes space, tab, newline and backslash as octal sequences in
/// the mount table.
fn unescape_mount(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &s[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
