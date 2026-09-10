# Hayabusa

Sigma correlation over the collected event logs. **Downloaded automatically** by
the *Locate the tooling* step.

Expected result: `hayabusa-<version>-win-x64.exe` in this folder.

To install it by hand:
<https://github.com/Yamato-Security/hayabusa/releases> → the `win-x64.zip`
asset → extract here.

The version number does not matter: the binary is found by pattern, and the
timeline subcommand is read from Hayabusa's own help output, so v3
(`csv-timeline`) and v4 (`dfir-timeline`) both work.

`hayabusa update-rules` writes its Sigma rules to `.\rules` relative to wherever
it runs. The console finds that folder wherever it landed and passes it with
`-r`, so no manual move is needed.
