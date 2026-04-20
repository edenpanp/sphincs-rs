use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SDKROOT");

    if std::env::consts::OS != "macos" {
        return;
    }

    if let Ok(sdk_root) = std::env::var("SDKROOT") {
        emit_sdk_search_path(&sdk_root);
        return;
    }

    let sdk_root = xcrun(&["--show-sdk-path"]);
    let Some(sdk_root) = sdk_root else {
        return;
    };
    emit_sdk_search_path(&sdk_root);

    if let Some(min_version) = xcrun(&["--sdk", "macosx", "--show-sdk-version"])
        .and_then(|version| deployment_target(&version))
    {
        println!("cargo:rustc-link-arg=-mmacosx-version-min={min_version}");
    }
}

fn emit_sdk_search_path(sdk_root: &str) {
    if sdk_root.is_empty() {
        return;
    }

    let lib_dir = Path::new(sdk_root).join("usr/lib");
    if lib_dir.is_dir() {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }
}

fn xcrun(args: &[&str]) -> Option<String> {
    let output = Command::new("xcrun").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}

fn deployment_target(sdk_version: &str) -> Option<String> {
    let mut parts = sdk_version.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    Some(format!("{major}.0.0"))
}
