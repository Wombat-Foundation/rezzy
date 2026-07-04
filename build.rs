fn main() {
    // Used to gate tests that depend on the res submodule
    if std::fs::read_dir("res").is_ok_and(|mut d| d.next().is_some()) {
        println!("cargo:rustc-cfg=has_res_submodule");
    }
    println!("cargo:rerun-if-changed=res");
}
