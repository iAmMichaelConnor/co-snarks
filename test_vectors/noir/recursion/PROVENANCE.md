# Verification key fixtures

`kat/recursion.json` is this package compiled with nargo 1.0.0 (`nargo compile`). The verification keys were written
by barretenberg `bb` 6.0.0:

```sh
bb write_vk -b kat/recursion.json -t noir-recursive -o out-pos  # out-pos/vk -> kat/recursion_vk_with_pos
bb write_vk -b kat/recursion.json -t evm-no-zk -o out-kec       # out-kec/vk -> kat/recursion_vk_with_kec
```

`-t noir-recursive-no-zk` gives the same `kat/recursion_vk_with_pos`.
