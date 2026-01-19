# Bugs

This folder contains patches that re-introduce real bugs into target full node
implementations.

| Patch File                                                                     | Implementation | Bug Type         |
|:-------------------------------------------------------------------------------|:---------------|:-----------------|
| `bitcoin-core/boolean-conversion/`                                             | Bitcoin Core   | Consensus        |
| `bitcoin-core/cve-2013-5700/`                                                  | Bitcoin Core   | Division by zero |
| `bitcoin-core/cve-2018-17144/`                                                 | Bitcoin Core   | Consensus        |
| `bitcoin-core/cve-2024-35202/`                                                 | Bitcoin Core   | Assert crash     |
| `bitcoin-core/findanddelete/`                                                  | Bitcoin Core   | Consensus        |
| `bitcoin-core/minimal-witness/`                                                | Bitcoin Core   | Consensus        |
| `bitcoin-core/unsigned-txver/`                                                 | Bitcoin Core   | Consensus        |
