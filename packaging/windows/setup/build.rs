//! Embeds the installer's application manifest and icon on Windows. The
//! manifest asks for Common Controls 6, without which Windows has no task
//! dialogs, and runs the installer as the user who started it: Windows
//! otherwise guesses that a program named "setup" wants administrator
//! rights.

fn main() {
    println!("cargo:rerun-if-changed=windows/factorseal-setup.rc");
    println!("cargo:rerun-if-changed=windows/factorseal-setup.manifest");
    println!("cargo:rerun-if-changed=../../../assets/logo/factorseal-app-icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    embed_resource::compile_for(
        "windows/factorseal-setup.rc",
        ["factorseal-setup"],
        embed_resource::ParamsIncludeDirs(["windows", "../../../assets/logo"]),
    )
    .manifest_required()
    .expect("embedding the installer's manifest and icon");
}
