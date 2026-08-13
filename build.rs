fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_avx512_support)");
    println!("cargo:rustc-check-cfg=cfg(has_avx512_host_support)");
    println!("cargo:rustc-check-cfg=cfg(has_res_submodule)");
    println!("cargo:rustc-check-cfg=cfg(tarpaulin_include)");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=TARGET");
    // Used to gate tests that depend on the res submodule
    if std::fs::read_dir("res").is_ok_and(|mut d| d.next().is_some()) {
        println!("cargo:rustc-cfg=has_res_submodule");
    }

    let rustc_version = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    if let Ok(output) = std::process::Command::new(rustc_version)
        .arg("--version")
        .output()
    {
        if let Ok(version_str) = String::from_utf8(output.stdout) {
            let parts: Vec<&str> = version_str.split_whitespace().collect();
            if parts.len() >= 2 && parts[1].starts_with("1.") {
                let minor = parts[1][2..].split('.').next().unwrap_or("0");
                if let Ok(minor_ver) = minor.parse::<u32>() {
                    if minor_ver >= 89 {
                        println!("cargo:rustc-cfg=has_avx512_support");
                    }
                }
            }
        }
    }

    // This cfg is only used to decide whether to suppress coverage on the
    // AVX-512 host-exercised path. It reflects the build host's capabilities,
    // but only when the target architecture itself can use that path.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx512f")
                && std::is_x86_feature_detected!("avx512bw")
                && std::is_x86_feature_detected!("vpclmulqdq")
            {
                println!("cargo:rustc-cfg=has_avx512_host_support");
            }
        }
    }

    println!("cargo:rerun-if-changed=res");
}
