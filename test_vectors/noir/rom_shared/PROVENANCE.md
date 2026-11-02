# Proof fixtures

`kat/rom_shared.json` and `kat/rom_shared.gz` are produced with nargo 1.0.0 (`../compile.sh`). The non-ZK proofs
were written by barretenberg `bb` 6.0.0:

```sh
bb prove -b kat/rom_shared.json -w kat/rom_shared.gz -t noir-recursive-no-zk --write_vk -o out-pos
bb prove -b kat/rom_shared.json -w kat/rom_shared.gz -t evm-no-zk --write_vk -o out-kec
# out-pos/proof -> kat/rom_shared_proof_with_pos, out-kec/proof -> kat/rom_shared_proof_with_kec
```
