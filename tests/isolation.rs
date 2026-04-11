use hexvault::cell::Cell;
use hexvault::stack::{self, Layer, LayerContext};
use hexvault::{generate_master_key, keys};

#[test]
fn test_cross_cell_decryption_failure() {
    // Threat Model #4: Blast radius from key compromise.
    // Goal: Confirm that keys derived for Cell A cannot decrypt ciphertext from Cell B.

    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let ctx = LayerContext::empty();

    // 1. Create two cells.
    let mut cell_a = Cell::new("cell-a".to_string());
    let cell_b_id = "cell-b";

    // 2. Store data in Cell A (AtRest).
    let plaintext = b"sensitive data";
    cell_a
        .store(&partition, "key1", plaintext, Layer::AtRest, &ctx)
        .unwrap();

    // 3. Seal directly using stack API to get raw ciphertext for Cell A.
    let sealed_in_a = stack::seal(&partition, "cell-a", Layer::AtRest, &ctx, plaintext).unwrap();

    // 4. Attempt to decrypt `sealed_in_a` using `cell-b`'s identity.
    let result = stack::peel(&partition, cell_b_id, Layer::AtRest, &ctx, &sealed_in_a);

    // 5. Assert failure. The authentication tag check MUST fail.
    assert!(
        result.is_err(),
        "Cell B keys successfully decrypted Cell A data!"
    );
}

#[test]
fn test_unique_key_derivation() {
    // Verify that identical plaintext sealed in two different cells produces
    // different ciphertext, confirming that HKDF derivation is cell-scoped.
    let master = generate_master_key().unwrap();
    let partition = keys::derive_partition_key(&master, "p").unwrap();
    let ctx = LayerContext::empty();
    let plaintext = b"identical payload";

    let sealed_a = stack::seal(&partition, "cell-a", Layer::AtRest, &ctx, plaintext).unwrap();
    let sealed_b = stack::seal(&partition, "cell-b", Layer::AtRest, &ctx, plaintext).unwrap();

    // Ciphertext must differ: same plaintext + different cell IDs = different derived keys.
    assert_ne!(
        sealed_a, sealed_b,
        "Identical plaintext in different cells produced identical ciphertext!"
    );
}
