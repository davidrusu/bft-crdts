# Towards BFT CRDT's

This repo contains a test rig for generating Byzantine examples for CRDT's

To generate the Byzantine examples:

```
QUICKCHECK_TESTS=1000 cargo test
```

Vary the number of tests to increase/decrease how likely it is to find an example.
