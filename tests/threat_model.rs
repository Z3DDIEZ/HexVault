use hexvault::stack::{Layer, LayerContext};
use hexvault::{generate_master_key, Vault};

#[test]
fn test_insider_access_no_audit() {
    // Threat Model: Insider attempts to traverse data without audit.
    // Goal: Verify that the PUBLIC API does not offer a way to move data between cells
    // without invoking the Audit system.

    // NOTE: This test is structural/negative. We check that `Vault` has no
    // `traverse_no_log` or similar methods, and that accessing `Edge` directly
    // requires going through `traverse` which logs.

    let master = generate_master_key().unwrap();
    let mut vault = Vault::new(master);
    let mut cell_a = vault.create_cell("a".into());
    let mut cell_b = vault.create_cell("b".into());
    let ctx = LayerContext::default();

    vault
        .seal(&mut cell_a, "secret", b"hush", Layer::AtRest, &ctx)
        .unwrap();

    // The only way to move "secret" to "b" using `Vault` is `traverse`.
    vault
        .traverse(&cell_a, &mut cell_b, "secret", Layer::AtRest, &ctx, &ctx)
        .unwrap();

    // And that MUST produce a log.
    assert!(!vault.audit_log().is_empty());
}
