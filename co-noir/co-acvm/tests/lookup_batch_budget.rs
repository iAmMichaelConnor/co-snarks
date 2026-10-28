use ark_bn254::Fr;
use co_acvm::mpc::lookup_read_count_batch_len;

#[test]
fn large_tables_respect_entry_and_gate_budgets() {
    // 512 of these tables previously formed a 64 MiB + 8-byte field frame.
    let tables = [4096; 512];
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(Some(4096), tables.into_iter()),
        256
    );
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(Some(17), tables.into_iter()),
        17
    );
}

#[test]
fn mixed_tables_are_budgeted_by_padded_lengths() {
    // The third table would fit if its padding were omitted.
    let tables = [3, 1023, (1 << 19) + 1, 1];
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(Some(4096), tables.into_iter()),
        2
    );
}

#[test]
fn singleton_and_empty_batches_make_progress() {
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(Some(4096), [1 << 22, 1].into_iter()),
        1
    );
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(Some(0), [4096, 4096].into_iter()),
        1
    );
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(Some(4096), [].into_iter()),
        0
    );
}

#[test]
fn explicitly_unbounded_batches_preserve_all_tables() {
    assert_eq!(
        lookup_read_count_batch_len::<Fr>(None, [1 << 22; 5000].into_iter()),
        5000
    );
}
