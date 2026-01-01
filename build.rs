use serde::Deserialize;
use std::env;
use std::process::Command;

const MACOS_TARGET_VERSION: &str = "15.0";
const IOS_TARGET_VERSION: &str = "13.0";

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

    // Handle RPath if required by the Swift libraries
    if swift_target_info.target.libraries_require_rpath {
        println!(
            "cargo:warning=Swift libraries require RPath for target {}",
            target
        );
        // Add rpath for Swift runtime libraries
        for path in &swift_target_info.paths.runtime_library_paths {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path);
        }
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

fn build_ios_cryptokit() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let profile = env::var("PROFILE").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_triple = env::var("TARGET").unwrap_or_default();

    println!("cargo:warning=Target env: '{}'", target_env);
    println!("cargo:warning=Target triple: '{}'", target_triple);
    println!("cargo:warning=Arch: '{}'", arch);

    // Determine iOS target based on architecture and environment
    let is_simulator = target_env == "sim" || target_triple.contains("sim");
    let target = if is_simulator {
        // iOS Simulator
        match arch.as_str() {
            "aarch64" => format!("{}-apple-ios{}-simulator", arch, IOS_TARGET_VERSION),
            "x86_64" => format!("{}-apple-ios{}-simulator", arch, IOS_TARGET_VERSION),
            _ => panic!("Unsupported iOS simulator architecture: {}", arch),
        }
    } else {
        // Physical iOS device
        match arch.as_str() {
            "aarch64" => format!("{}-apple-ios{}", arch, IOS_TARGET_VERSION),
            _ => panic!("Unsupported iOS device architecture: {}", arch),
        }
    };

    println!("cargo:warning=Using Swift target: '{}'", target);

    let swift_target_info_str = Command::new("swift")
        .args(&["-target", &target, "-print-target-info"])
        .output()
        .unwrap()
        .stdout;
    let swift_target_info: SwiftTarget = serde_json::from_slice(&swift_target_info_str)
        .inspect_err(|e| eprint!("{}", e))
        .unwrap();

    let arch_rs = if arch == "aarch64" {
        "arm64".to_string()
    } else {
        arch.clone()
    };

    let swift_scratch_path = format!("{out_dir}/swift_build");
    println!(
        "cargo:warning=Building swift for iOS profile {profile}, arch {arch}, arch_rs {arch_rs}"
    );

    // Get the appropriate SDK path
    let sdk_name = if is_simulator {
        "iphonesimulator"
    } else {
        "iphoneos"
    };

    let sdk_path_output = Command::new("xcrun")
        .args(&["--show-sdk-path", "--sdk", sdk_name])
        .output()
        .unwrap()
        .stdout;
    let sdk_path = String::from_utf8(sdk_path_output).unwrap();
    let sdk_path = sdk_path.trim();

    // Compile all Swift files directly using swiftc
    let swift_files = vec![
        "Sources/CryptoKit.swift",
        "Sources/Asymmetric/Curve25519.swift",
        "Sources/Asymmetric/P256.swift",
        "Sources/Asymmetric/P384.swift",
        "Sources/Asymmetric/P521.swift",
        "Sources/Authentication/HMAC.swift",
        "Sources/Hashing/Hashing.swift",
        "Sources/KeyDerivation/HKDF.swift",
        "Sources/Keys/SymmetricKeys.swift",
        "Sources/Quantum/KEM.swift",
        "Sources/Quantum/Signature.swift",
        "Sources/Symmetric/AES.swift",
        "Sources/Symmetric/ChaCha20Poly1305.swift",
    ];

    let output_lib = format!("{}/libcryptokit.a", swift_scratch_path);

    // Create the output directory
    std::fs::create_dir_all(&swift_scratch_path).unwrap();

    let mut swiftc_command = Command::new("swiftc");
    swiftc_command
        .env(
            "DEVELOPER_DIR",
            "/Applications/Xcode.app/Contents/Developer",
        )
        .current_dir("swift")
        .args(&[
            "-emit-library",
            "-static",
            "-target",
            &target,
            "-sdk",
            sdk_path,
            "-module-name",
            "cryptokit",
            "-O",
            "-o",
            &output_lib,
        ])
        .args(&swift_files);

    if !swiftc_command.status().unwrap().success() {
        panic!("Swift library cryptokit compilation failed for iOS")
    }

    swift_target_info
        .paths
        .runtime_library_paths
        .iter()
        .for_each(|path| {
            println!("cargo:rustc-link-search=native={}", path);
        });

    // Link to our compiled static library
    println!("cargo:rustc-link-search=native={}", swift_scratch_path);
    println!("cargo:rustc-link-lib=static=cryptokit");

    // Add framework linking for iOS
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CryptoKit");

    println!("cargo:rerun-if-changed=swift/Sources/*.swift");
    println!(
        "cargo:rustc-env=IPHONEOS_DEPLOYMENT_TARGET={}",
        IOS_TARGET_VERSION
    )
}

fn main() {
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target.as_str() {
        "macos" => build_mac_cryptokit(),
        "ios" => build_ios_cryptokit(),
        _ => {
            // For other platforms, we don't build the Swift library
            println!(
                "cargo:warning=Skipping Swift build for unsupported platform: {}",
                target
            );
        }
    }
}
