# evidence/

Output of the collection. CyLR writes `<case>.zip` here and the console unpacks
it alongside, so the event logs end up under:

    evidence/<case>/C/Windows/System32/winevt/Logs/

This folder is the default scope of the YARA scan, and the source Hayabusa
reads. Nothing here is written by hand.

Treat its contents as evidence: the seals in the report are SHA-256 hashes of
these files, and altering them breaks the chain of custody.
