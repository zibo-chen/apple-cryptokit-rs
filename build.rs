use serde::Deserialize;
use std::env;
use std::process::Command;

const MACOS_TARGET_VERSION: &str = "15.0";

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwiftTargetInfo {
    triple: String,
    unversioned_triple: String,
    module_triple: String,
    swift_runtime_compatibility_version: Option<String>,
    #[serde(rename = "librariesRequireRPath")]
    libraries_require_rpath: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwiftPaths {
    runtime_library_paths: Vec<String>,
    runtime_library_import_paths: Vec<String>,
    runtime_resource_path: String,
}

#[derive(Debug, Deserialize)]
struct SwiftTarget {
    target: SwiftTargetInfo,
    paths: SwiftPaths,
}

fn build_mac_cryptokit() {
    let out_dir = env::var("OUT_DIR").unwrap();
    // println!("cargo:warning=OUT_DIR {out_dir}");
    let profile = env::var("PROFILE").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let target = format!("{}-apple-macosx{}", arch, MACOS_TARGET_VERSION);
    // println!("cargo:warning=Target {target}");

    let swift_target_info_str = Command::new("swift")
        .args(&["-target", &target, "-print-target-info"])
        .output()
        .unwrap()
        .stdout;
    let swift_target_info: SwiftTarget = serde_json::from_slice(&swift_target_info_str)
        .inspect_err(|e| eprint!("{}", e))
        .unwrap();
    if swift_target_info.target.libraries_require_rpath {
        panic!(
            "Libraries require RPath! Change minimum MacOS value to fix. Target: {}",
            target
        )
    }

    let arch_rs = if arch == "aarch64" {
        // :HACK: swift arch vs rust arch
        "arm64".to_string()
    } else {
        arch.clone()
    };

    let swift_scratch_path = format!("{out_dir}/swift_build");
    println!("cargo:warning=Building swift for profile {profile}, arch {arch}, arch_rs {arch_rs}");
    if !Command::new("swift")
        .args(&[
            "build",
            "-c",
            &profile, // "--arch", &arch,
            "--triple",
            &target,
            "--scratch-path",
            &swift_scratch_path,
        ])
        .current_dir("swift")
        .status()
        .unwrap()
        .success()
    {
        panic!("Swift library cryptokit compilation failed")
    }

    swift_target_info
        .paths
        .runtime_library_paths
        .iter()
        .for_each(|path| {
            // println!("cargo:warning=rustc-link-search=native={}", path);
            println!("cargo:rustc-link-search=native={}", path);
        });

    println!("cargo:rustc-link-search=native={swift_scratch_path}/{arch}-apple-macosx/{profile}");
    println!("cargo:rustc-link-lib=static=cryptokit");
    println!("cargo:rerun-if-changed=swift/Sources/*.swift");
    println!(
        "cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET={}",
        MACOS_TARGET_VERSION
    )
}

fn main() {
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target == "macos" {
        build_mac_cryptokit();
    }
}
