# Fuzzamoto LibAFL

LibAFL based fuzzer for Fuzzamoto operating on [fuzzamoto-ir](../fuzzamoto-ir)
programs. This fuzzer exclusively operates on the [IR
scenario](../fuzzamoto-scenarios/bin/ir.rs).

```
         ------------------------------------------------
         |                                              |
---------|------------ Nyx VM ----------------------    |
|        |                                         |    |
|  -------------                     ------------- |    |
|  |   ir.rs   | <------ p2p ------> | bitcoind  | |    |
|  -------------                     ------------- |    |
|        ^                                         |    |
---------|------------------------------------------    |
         |                                              |
         ----------                                Interesting?
                  |                                     |
 Compile IR to sequence of p2p messages                 |
                  ^                                     |
                  |                                     |
                  |                                     |
    Pick input from corpus and mutate                   |
                  |                                     |
                  |                                     |
          -----------------                             |
          |  Corpus (IR)  |  <---------------------------
          -----------------
```
