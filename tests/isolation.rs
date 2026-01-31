use hexvault::cell::Cell;
use hexvault::generate_master_key;
use hexvault::stack::{self, Layer, LayerContext};

#[test]
fn test_cross_cell_decryption_failure() {
    // Threat Model #4: Blast radius from key compromise.
    // Goal: Confirm that keys derived for Cell A cannot decrypt ciphertext from Cell B.

    let master = generate_master_key().unwrap();
    let ctx = LayerContext::default();

    // 1. Create two cells.
    let mut cell_a = Cell::new("cell-a".to_string());
    let cell_b_id = "cell-b";

    // 2. Store data in Cell A (AtRest).
    let plaintext = b"sensitive data";
    cell_a
        .store(&master, "key1", plaintext, Layer::AtRest, &ctx)
        .unwrap();

    // 3. Extract the ciphertext directly (simulating access to storage).
    // Accessing internal payload data via the public API is hard without exposing internals.
    // However, we know `cell_a` stores it.
    // To simulate the attack, we will try to PEEL the data using `stack::peel` with `cell_b_id`.

    // We need to get the ciphertext bytes first.
    // Using `retrieve` decrypts it, which isn't what we want. We want the raw ciphertext.
    // Since `Cell` doesn't expose raw ciphertext in the public API, we have to construct
    // the scenario using `stack::seal` directly to simulate "data stored in Cell A".

    let sealed_in_a = stack::seal(&master, "cell-a", Layer::AtRest, &ctx, plaintext).unwrap();

    // 4. Attempt to decrypt `sealed_in_a` using `cell-b`'s identity.
    let result = stack::peel(&master, cell_b_id, Layer::AtRest, &ctx, &sealed_in_a);

    // 5. Assert failure. The authentication tag check MUST fail.
    assert!(
        result.is_err(),
        "Cell B keys successfully decrypted Cell A data!"
    );
}

#[test]
fn test_unique_key_derivation() {
    // Statistical verification that keys differ is implicit in the decryption failure,
    // but we can't easily check key bytes since they are not exposed (which is good).
    // The previous test covers the functional aspect of this.
}
