#![forbid(unsafe_code)]

fn main() {
    println!("cargo:rerun-if-changed=assets/windows.rc");
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile_for("assets/windows.rc", ["wg-easy"], embed_resource::NONE)
            .manifest_required()
            .expect("compile Windows application icon");
    }
}
