//! Build glue for the optional `libote` feature.
//!
//! Compiles `cpp/libote_shim.cc` against a local libOTe checkout and links its static libraries.
//! Nothing here runs for the default (sl-oblivious) build.
//!
//! The libOTe tree is expected at `<repo>/libOTe`, configured and built with
//!
//! ```text
//! cmake -S . -B out/build/linux -DCMAKE_BUILD_TYPE=Release -DFETCH_AUTO=ON \
//!       -DENABLE_LOGVOLE=OFF -DENABLE_SOFTSPOKEN_OT=ON -DENABLE_MR=ON \
//!       -DENABLE_SIMPLESTOT=ON -DENABLE_SPIN=OFF -DENABLE_BITPOLYMUL=OFF
//! cmake --build out/build/linux --target libOTe --parallel
//! ```
//!
//! Override the location with `LIBOTE_DIR`.
//!
//! The flags mirror `<build>/libOTe/CMakeFiles/libOTe.dir/flags.make`: the shim instantiates
//! libOTe's templates, so it must see the same include paths, the same `NDEBUG`, and the same
//! instruction-set flags as the library it links against.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=cpp/libote_shim.cc");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LIBOTE_DIR");

    if std::env::var_os("CARGO_FEATURE_LIBOTE").is_none() {
        return;
    }

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let libote = match std::env::var_os("LIBOTE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => manifest.join("../libOTe"),
    };
    let libote = libote.canonicalize().unwrap_or(libote);
    let build = libote.join("out/build/linux");
    if !build.exists() {
        panic!(
            "libOTe is not configured at {}; see dklst-bbs/build.rs for the cmake invocation",
            build.display()
        );
    }

    // Same include paths as the library build, plus the header-only dependencies it pulls in.
    let includes = [
        build.clone(),
        libote.clone(),
        build.join("cryptoTools"),
        libote.join("cryptoTools"),
        build.join("coproto"),
        libote.join("out/coproto"),
        build.join("macoro"),
        libote.join("out/macoro"),
        libote.join("out/function2/include"),
        libote.join("out/libdivide"),
        libote.join("cryptoTools/thirdparty/span-lite/include"),
    ];

    let mut cc = cc::Build::new();
    cc.cpp(true)
        .std("c++20")
        .opt_level(3)
        .warnings(false)
        .define("NDEBUG", None)
        .define("CRYPTOTOOLS_EDWARDS25519_ASM", "1")
        .file("cpp/libote_shim.cc");
    for flag in [
        "-maes",
        "-msse2",
        "-msse3",
        "-mssse3",
        "-msse4.1",
        "-mpclmul",
        "-mavx",
        "-mavx2",
        "-mavx512f",
        "-mavx512vl",
        "-mavx512bw",
        "-mavx512dq",
        "-mbmi2",
    ] {
        cc.flag_if_supported(flag);
    }
    for include in &includes {
        if include.exists() {
            cc.include(include);
        }
    }
    cc.compile("libote_shim");

    // Static libraries, most dependent first. `cryptoTools` and `coproto` reference each other, so
    // both are listed twice rather than relying on a linker group.
    let wanted = ["libOTe", "cryptoTools", "coproto", "macoro"];
    for name in wanted.iter() {
        match find_static(&build, name) {
            Some(path) => {
                let dir = path.parent().expect("parent").to_path_buf();
                println!("cargo:rustc-link-search=native={}", dir.display());
                println!("cargo:rerun-if-changed={}", path.display());
            }
            None => panic!("could not find lib{name}.a under {}", build.display()),
        }
    }
    for name in wanted.iter() {
        println!("cargo:rustc-link-lib=static={name}");
    }
    for name in ["cryptoTools", "coproto", "macoro"] {
        println!("cargo:rustc-link-lib=static={name}");
    }
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=m");

    // libOTe is built as a non-PIC static library while Rust links position-independent
    // executables by default; ask the linker for a plain executable instead of rebuilding the
    // whole library with `-fPIC`.
    println!("cargo:rustc-link-arg=-no-pie");
}

fn find_static(root: &Path, name: &str) -> Option<PathBuf> {
    let target = format!("lib{name}.a");
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|value| value.to_str()) == Some(target.as_str()) {
                return Some(path);
            }
        }
    }
    None
}
