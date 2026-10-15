//! Builds armm_oracle.dll from the QEMU sources with MSYS2's CLANG64
//! toolchain (QEMU's configure, meson and ninja), and tells src/lib.rs where
//! the DLL is through `ARMM_ORACLE_DLL_DIR`.
//!
//! Nothing under the crate directory is written: QEMU is configured from a
//! copy of its source tree in OUT_DIR (`qemu-src/`). The top level and every
//! directory on the path of a file that `patches/*.patch` touches are real
//! directories holding copies of their files and junctions to their
//! subdirectories; all other directories are junctions to the QEMU sources.
//! The patches are applied to the copies only, and `oracle` is a junction to
//! `frontend/`. Configure and build output go to `OUT_DIR/build`; the DLL and
//! the MSYS2 runtime DLLs it needs go to `OUT_DIR/dist`.
//!
//! Without MSYS2 (or on a non-Windows host) the DLL is not built: build.rs
//! prints a warning and passes the reason in `ARMM_ORACLE_NOT_BUILT`, so the
//! crate still compiles and `Oracle::new` returns that reason as an error.
//!
//! Environment:
//!   MSYS2_ROOT            MSYS2 install directory (default C:\msys64)
//!   ARMM_ORACLE_QEMU_DIR  QEMU source tree to use instead of the submodule

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONFIGURE_ARGS: &[&str] = &[
    "--target-list=arm-softmmu",
    "--without-default-features",
    "--enable-tcg",
    "--disable-docs",
    "--disable-tools",
    "--disable-guest-agent",
    "--disable-plugins",
    "--disable-werror",
];

/// Files the build needs from MSYS2, and the CLANG64 package that brings
/// each (lld and llvm-tools come with clang).
const PACKAGES: &[(&str, &str)] = &[
    ("clang64/bin/clang.exe", "mingw-w64-clang-x86_64-clang"),
    ("clang64/bin/ld.lld.exe", "mingw-w64-clang-x86_64-clang"),
    ("clang64/bin/llvm-readobj.exe", "mingw-w64-clang-x86_64-clang"),
    ("clang64/bin/meson.exe", "mingw-w64-clang-x86_64-meson"),
    ("clang64/bin/ninja.exe", "mingw-w64-clang-x86_64-ninja"),
    ("clang64/bin/pkgconf.exe", "mingw-w64-clang-x86_64-pkgconf"),
    ("clang64/bin/python3.exe", "mingw-w64-clang-x86_64-python"),
    ("clang64/lib/pkgconfig/glib-2.0.pc", "mingw-w64-clang-x86_64-glib2"),
];

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    for path in ["frontend", "include", "patches", ".gitmodules"] {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(head) = submodule_head(&manifest.join("qemu")) {
        println!("cargo:rerun-if-changed={}", head.display());
    }
    println!("cargo:rerun-if-env-changed=MSYS2_ROOT");
    println!("cargo:rerun-if-env-changed=ARMM_ORACLE_QEMU_DIR");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if !cfg!(windows) || target_os != "windows" {
        skip("the oracle is only built on Windows hosts so far", &[]);
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let Some(msys) = find_msys2() else { return };
    let qemu = qemu_source(&manifest, &out);
    let tools = ToolEnv::new(&msys, &out);

    let src = out.join("qemu-src");
    let build = out.join("build");
    let dist = out.join("dist");
    make_source_tree(&manifest, &qemu, &src, &out);
    configure(&msys, &tools, &src, &build, &out);
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "0".into());
    run(
        Command::new(msys.join("clang64/bin/ninja.exe"))
            .arg("-C")
            .arg(&build)
            .args(["-j", &jobs, "armm-oracle"]),
        &tools,
        "ninja armm-oracle",
        &out,
    );
    stage_dist(&msys, &tools, &build.join("oracle/armm_oracle.dll"), &dist, &out);
    println!("cargo:rustc-env=ARMM_ORACLE_DLL_DIR={}", dist.display());
}

fn skip(reason: &str, hints: &[&str]) {
    println!("cargo:warning=qemu-armm-oracle: {reason}; the oracle DLL is not built and Oracle::new will return an error");
    for hint in hints {
        println!("cargo:warning=qemu-armm-oracle: {hint}");
    }
    println!("cargo:rustc-env=ARMM_ORACLE_NOT_BUILT={reason}");
}

fn fail(msg: &str) -> ! {
    eprintln!("\nqemu-armm-oracle build error:\n{msg}\n");
    panic!("qemu-armm-oracle: {}", msg.lines().next().unwrap_or(msg));
}

/// The submodule's HEAD file, which changes exactly when another QEMU commit
/// is checked out; None when the submodule is not checked out.
fn submodule_head(qemu: &Path) -> Option<PathBuf> {
    let dotgit = qemu.join(".git");
    if dotgit.is_dir() {
        return Some(dotgit.join("HEAD"));
    }
    let s = fs::read_to_string(&dotgit).ok()?;
    let dir = s.trim().strip_prefix("gitdir:")?;
    Some(qemu.join(dir.trim()).join("HEAD"))
}

/// `$ARMM_ORACLE_QEMU_DIR`, else the checked-out submodule, else the
/// submodule's commit fetched into OUT_DIR. Cargo does not check the
/// submodule out for git dependencies (`update = none` in .gitmodules).
fn qemu_source(manifest: &Path, out: &Path) -> PathBuf {
    if let Some(dir) = env::var_os("ARMM_ORACLE_QEMU_DIR") {
        let dir = PathBuf::from(dir);
        if !dir.join("configure").is_file() {
            fail(&format!("ARMM_ORACLE_QEMU_DIR={} is not a QEMU source tree", dir.display()));
        }
        return dir;
    }
    let sub = manifest.join("qemu");
    if sub.join("configure").is_file() {
        if fs::read(sub.join("configure")).unwrap().contains(&b'\r') {
            fail(&format!(
                "{} has CRLF line endings (git core.autocrlf=true), which sh cannot run.\n\
                 Check the submodule out again with LF endings:\n    \
                 git -C qemu config core.autocrlf false\n    \
                 git -C qemu rm -q -r --cached .\n    \
                 git -C qemu reset -q --hard",
                sub.join("configure").display()
            ));
        }
        return sub;
    }

    let git = |args: &[&str]| -> String {
        let o = Command::new("git")
            .current_dir(manifest)
            .args(args)
            .output()
            .unwrap_or_else(|e| fail(&format!("cannot run git (install Git for Windows): {e}")));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    // Cargo's checkouts have no gitlink in the index; a repo without commits has no HEAD.
    let gitlink = format!("{}\n{}", git(&["ls-tree", "HEAD", "--", "qemu"]), git(&["ls-files", "-s", "--", "qemu"]));
    let commit = gitlink
        .split_whitespace()
        .find(|w| w.len() == 40 && w.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string);
    let url = git(&["config", "-f", ".gitmodules", "submodule.qemu.url"]);
    let (Some(commit), false) = (commit, url.is_empty()) else {
        fail(&format!(
            "the qemu submodule is not checked out at {} and its commit is unknown.\n\
             Run `git -c core.autocrlf=false submodule update --init --checkout qemu` in the crate directory.",
            sub.display()
        ));
    };

    let dir = out.join("qemu-upstream");
    let stamp = out.join("qemu-upstream.commit");
    if dir.join("configure").is_file() && fs::read_to_string(&stamp).ok().as_deref() == Some(&commit) {
        return dir;
    }
    let tmp = out.join("qemu-upstream.tmp");
    for d in [&dir, &tmp] {
        if d.exists() {
            fs::remove_dir_all(d).unwrap();
        }
    }
    let steps: [&[&str]; 4] = [
        &["init", "-q"],
        &["config", "core.autocrlf", "false"],
        &["fetch", "-q", "--depth", "1", "--no-tags", &url, &commit],
        &["checkout", "-q", "FETCH_HEAD"],
    ];
    fs::create_dir_all(&tmp).unwrap();
    for args in steps {
        let o = Command::new("git").current_dir(&tmp).args(args).output().unwrap();
        if !o.status.success() {
            fail(&format!(
                "fetching QEMU {commit} from {url} failed (git {}):\n{}\
                 Check the network, or set ARMM_ORACLE_QEMU_DIR to a QEMU checkout of that commit.",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr)
            ));
        }
    }
    fs::rename(&tmp, &dir).unwrap();
    fs::write(&stamp, &commit).unwrap();
    dir
}

/// None (after a warning) when MSYS2 itself is absent; an MSYS2 install
/// that lacks packages is an error, since someone is setting it up.
fn find_msys2() -> Option<PathBuf> {
    let root = env::var_os("MSYS2_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\msys64"));
    let mut all: Vec<&str> = PACKAGES.iter().map(|p| p.1).collect();
    all.dedup();
    if !root.join("usr/bin/sh.exe").is_file() {
        skip(
            &format!("MSYS2 not found at {} (set MSYS2_ROOT to its install directory)", root.display()),
            &[
                "to build the oracle, install MSYS2 from https://www.msys2.org/, then in an MSYS2 shell run:",
                &format!("pacman -S --needed {}", all.join(" ")),
            ],
        );
        return None;
    }
    let mut missing: Vec<&str> =
        PACKAGES.iter().filter(|(file, _)| !root.join(file).is_file()).map(|p| p.1).collect();
    missing.dedup();
    if !missing.is_empty() {
        fail(&format!(
            "MSYS2 at {} is missing CLANG64 packages needed to build the oracle: {}.\n\
             In an MSYS2 shell run:\n    pacman -S --needed {}",
            root.display(),
            missing.join(", "),
            all.join(" ")
        ));
    }
    Some(root)
}

/// Environment for MSYS2 tools: CLANG64 first on PATH, and nothing of
/// cargo's own variables (configure reads every variable as a shell variable).
struct ToolEnv(Vec<(OsString, OsString)>);

impl ToolEnv {
    fn new(msys: &Path, out: &Path) -> ToolEnv {
        const KEEP: &[&str] = &[
            "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
            "USERPROFILE", "USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
            "PROGRAMDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "HTTP_PROXY",
            "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
        ];
        let mut vars: Vec<(OsString, OsString)> = env::vars_os()
            .filter(|(k, _)| KEEP.contains(&k.to_string_lossy().to_uppercase().as_str()))
            .collect();
        let mut path = vec![msys.join("clang64/bin"), msys.join("usr/bin")];
        if let Some(p) = env::var_os("PATH") {
            path.extend(env::split_paths(&p));
        }
        vars.push(("PATH".into(), env::join_paths(path).unwrap()));
        vars.push(("MSYSTEM".into(), "CLANG64".into()));
        // Keeps Python from writing __pycache__ into the junctioned source dirs.
        vars.push(("PYTHONPYCACHEPREFIX".into(), out.join("pycache").into()));
        ToolEnv(vars)
    }
}

fn run(cmd: &mut Command, tools: &ToolEnv, what: &str, out: &Path) -> String {
    cmd.env_clear().envs(tools.0.iter().map(|(k, v)| (k, v)));
    let output = cmd
        .output()
        .unwrap_or_else(|e| fail(&format!("cannot run {what} ({:?}): {e}", cmd.get_program())));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let log = out.join("logs").join(format!("{}.log", what.replace(' ', "-")));
    let _ = fs::create_dir_all(log.parent().unwrap());
    let _ = fs::write(&log, &text);
    if !output.status.success() {
        let lines: Vec<&str> = text.lines().collect();
        let tail = lines[lines.len().saturating_sub(60)..].join("\n");
        fail(&format!(
            "{what} failed ({}). Full log: {}\n...\n{tail}",
            output.status,
            log.display()
        ));
    }
    text
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Fill `src` with junctions to the submodule's directories and copies of
/// its files, as described at the top of this file.
fn make_source_tree(manifest: &Path, qemu: &Path, src: &Path, out: &Path) {
    let patched = apply_patches(manifest, qemu, out);
    let mut real_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    // Meson downloads wrap subprojects into subprojects/; keep that in OUT_DIR.
    real_dirs.insert(PathBuf::from("subprojects"));
    for rel in patched.iter().map(|p| &p.0) {
        real_dirs.extend(rel.ancestors().skip(1).filter(|a| !a.as_os_str().is_empty()).map(Path::to_path_buf));
    }
    mirror(qemu, src, Path::new(""), &real_dirs, &patched);
    ensure_junction(&src.join("oracle"), &manifest.join("frontend"));
}

fn mirror(
    from: &Path,
    to: &Path,
    rel: &Path,
    real_dirs: &BTreeSet<PathBuf>,
    patched: &[(PathBuf, Vec<u8>)],
) {
    // A junction left by an earlier build: writing through it would change the QEMU sources.
    if fs::symlink_metadata(to).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::remove_dir(to).unwrap();
    }
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let skip = if rel.as_os_str().is_empty() {
            name == ".git" || name == "oracle"
        } else {
            name.to_string_lossy().starts_with('.') || name == "packagecache"
        };
        if skip {
            continue;
        }
        let r = rel.join(&name);
        let (src, dst) = (entry.path(), to.join(&name));
        if entry.file_type().unwrap().is_dir() || src.is_dir() {
            // A real directory stays real: a junction back could show sources older than
            // their objects, which ninja would not rebuild. Under subprojects/ it is a meson download.
            let was_real = rel != Path::new("subprojects")
                && fs::symlink_metadata(&dst).is_ok_and(|m| m.is_dir());
            if real_dirs.contains(&r) || was_real {
                mirror(&src, &dst, &r, real_dirs, patched);
            } else {
                ensure_junction(&dst, &src);
            }
        } else {
            let data = match patched.iter().find(|p| p.0 == r) {
                Some(p) => p.1.clone(),
                None => fs::read(&src).unwrap(),
            };
            write_if_changed(&dst, &data);
        }
    }
}

/// Unchanged files keep their timestamps, so ninja does not rerun meson.
fn write_if_changed(path: &Path, data: &[u8]) {
    if fs::read(path).ok().as_deref() != Some(data) {
        fs::write(path, data).unwrap_or_else(|e| fail(&format!("writing {}: {e}", path.display())));
    }
}

fn ensure_junction(link: &Path, target: &Path) {
    if let Ok(meta) = fs::symlink_metadata(link) {
        if !meta.file_type().is_symlink() {
            // A real directory, e.g. a subproject meson downloaded here.
            return;
        }
        if fs::canonicalize(link).ok() == fs::canonicalize(target).ok() {
            return;
        }
        fs::remove_dir(link).unwrap();
    }
    let backslash = |p: &Path| p.to_string_lossy().replace('/', "\\");
    let status = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(backslash(link))
        .arg(backslash(target))
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    if !status.success() {
        fail(&format!("mklink /J {} {} failed", link.display(), target.display()));
    }
}

/// Apply patches/*.patch to copies of the files they touch; returns each
/// touched path (relative to qemu/) with its patched contents.
fn apply_patches(manifest: &Path, qemu: &Path, out: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut patches: Vec<PathBuf> = fs::read_dir(manifest.join("patches"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "patch"))
        .collect();
    patches.sort();
    let mut touched: BTreeSet<PathBuf> = BTreeSet::new();
    if !patches.is_empty() {
        let o = Command::new("git")
            .current_dir(out)
            .env("GIT_CEILING_DIRECTORIES", out)
            .args(["apply", "--numstat", "-z"])
            .args(&patches)
            .output()
            .unwrap_or_else(|e| fail(&format!("cannot run git (install Git for Windows or MSYS2's git): {e}")));
        if !o.status.success() {
            fail(&format!("git apply --numstat failed:\n{}", String::from_utf8_lossy(&o.stderr)));
        }
        for rec in String::from_utf8_lossy(&o.stdout).split('\0') {
            if let Some(path) = rec.splitn(3, '\t').nth(2).filter(|p| !p.is_empty()) {
                touched.insert(PathBuf::from(path));
            }
        }
    }

    let stage = out.join("patch-stage");
    if stage.exists() {
        fs::remove_dir_all(&stage).unwrap();
    }
    for rel in &touched {
        let dst = stage.join(rel);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::copy(qemu.join(rel), &dst)
            .unwrap_or_else(|e| fail(&format!("patched file qemu/{} is missing: {e}", rel.display())));
    }
    for p in &patches {
        // -C2: tolerate upstream changes to the outer context lines.
        let git = |extra: &[&str]| {
            Command::new("git")
                .current_dir(&stage)
                .env("GIT_CEILING_DIRECTORIES", out)
                // Outside a repository git apply still follows a global core.autocrlf=true and writes CRLF.
                .args(["-c", "core.autocrlf=false", "apply"])
                .args(extra)
                .args(["-C2", "--whitespace=nowarn"])
                .arg(p)
                .output()
                .unwrap_or_else(|e| fail(&format!("cannot run git (install Git for Windows or MSYS2's git): {e}")))
        };
        if git(&["--reverse", "--check"]).status.success() {
            continue;
        }
        let o = git(&[]);
        if !o.status.success() {
            fail(&format!(
                "{} no longer applies to the qemu submodule:\n{}\
                 Refresh the patch against the checked-out QEMU (scripts/apply-patches.sh uses --3way).",
                p.display(),
                String::from_utf8_lossy(&o.stderr)
            ));
        }
    }
    touched.into_iter().map(|rel| {
        let data = fs::read(stage.join(&rel)).unwrap();
        (rel, data)
    }).collect()
}

fn configure(msys: &Path, tools: &ToolEnv, src: &Path, build: &Path, out: &Path) {
    let stamp = build.join("armm-oracle-configure");
    let want = format!("{}\n{}\n", slash(src), CONFIGURE_ARGS.join(" "));
    if build.join("build.ninja").is_file() && fs::read_to_string(&stamp).ok().as_deref() == Some(&want) {
        return;
    }
    if build.exists() {
        fs::remove_dir_all(build).unwrap();
    }
    fs::create_dir_all(build).unwrap();
    run(
        Command::new(msys.join("usr/bin/sh.exe"))
            .arg(slash(&src.join("configure")))
            .args(CONFIGURE_ARGS)
            .current_dir(build),
        tools,
        "configure",
        out,
    );
    fs::write(&stamp, want).unwrap();
}

/// Copy the DLL and every DLL it loads from MSYS2's clang64/bin into `dist`.
fn stage_dist(msys: &Path, tools: &ToolEnv, dll: &Path, dist: &Path, out: &Path) {
    fs::create_dir_all(dist).unwrap();
    let bin = msys.join("clang64/bin");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut todo = vec![dll.to_path_buf()];
    while let Some(file) = todo.pop() {
        copy_if_changed(&file, &dist.join(file.file_name().unwrap()));
        let imports = run(
            Command::new(bin.join("llvm-readobj.exe")).arg("--coff-imports").arg(&file),
            tools,
            "llvm-readobj",
            out,
        );
        for name in imports.lines().filter_map(|l| l.trim().strip_prefix("Name: ")) {
            let dep = bin.join(name);
            if seen.insert(name.to_ascii_lowercase()) && dep.is_file() {
                todo.push(dep);
            }
        }
    }
}

fn copy_if_changed(from: &Path, to: &Path) {
    let stamp = |p: &Path| fs::metadata(p).ok().map(|m| (m.len(), m.modified().ok()));
    if stamp(from) != stamp(to) {
        fs::copy(from, to)
            .unwrap_or_else(|e| fail(&format!("copying {} to {}: {e}", from.display(), to.display())));
    }
}
