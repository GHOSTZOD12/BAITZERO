fn main() {
    println!("cargo:rerun-if-env-changed=LINK_PROTECTION_TEST_CONFIG");
    println!("cargo:rerun-if-env-changed=LINK_PROTECTION_IDENTITY");

    // Package identity selection:
    // - Default (unset or "production"): Production identity ("link-protection-system")
    // - Explicit "candidate": Candidate identity ("link-protection-candidate")
    // - Any other value: Fail closed with panic
    let identity = std::env::var("LINK_PROTECTION_IDENTITY").unwrap_or_else(|_| "production".to_string());
    let (package_name, app_id, assembly_name) = match identity.as_str() {
        "production" => (
            "link-protection-system",
            "linkprotectionsystem",
            "link-protection-system",
        ),
        "candidate" => (
            "link-protection-candidate",
            "linkprotectioncandidate",
            "link-protection-system",
        ),
        other => {
            panic!(
                "FAIL-CLOSED: Unknown LINK_PROTECTION_IDENTITY '{}'. Must be 'production' or 'candidate'.",
                other
            );
        }
    };

    let mut manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="{assembly_name}" type="win32"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
"#,
        assembly_name = assembly_name
    );

    // When running unpackaged cargo test, the Windows NT loader aborts with 0xc0000142 (STATUS_DLL_INIT_FAILED)
    // if the PE manifest contains an <msix> element without an active MSIX package execution envelope.
    // For packaged builds, the full <msix> manifest is embedded to match the package identity.
    if std::env::var("LINK_PROTECTION_TEST_CONFIG").is_err() {
        manifest.push_str(&format!(
            r#"  <msix xmlns="urn:schemas-microsoft-com:msix.v1"
        publisher="CN=Link Protection Team"
        packageName="{package_name}"
        applicationId="{app_id}"/>
"#,
            package_name = package_name,
            app_id = app_id
        ));
    }
    manifest.push_str("</assembly>\n");

    let windows_attributes = tauri_build::WindowsAttributes::new().app_manifest(manifest);
    let attributes = tauri_build::Attributes::new().windows_attributes(windows_attributes);
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}


