#![allow(missing_docs)]

fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_avx512_support)");
    println!("cargo:rustc-check-cfg=cfg(has_avx512_host_support)");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=TARGET");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    if let Ok(output) = std::process::Command::new(rustc).arg("--version").output() {
        if let Ok(version) = String::from_utf8(output.stdout) {
            let mut parts = version.split_whitespace();
            let _ = parts.next();
            if parts
                .next()
                .and_then(|version| version.strip_prefix("1."))
                .and_then(|minor| minor.split('.').next())
                .and_then(|minor| minor.parse::<u32>().ok())
                .is_some_and(|minor| minor >= 89)
            {
                println!("cargo:rustc-cfg=has_avx512_support");
            }
        }
    }

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("vpclmulqdq")
        {
            println!("cargo:rustc-cfg=has_avx512_host_support");
        }
    }
}
