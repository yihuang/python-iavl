`python-iavl` implements [iavl tree](https://github.com/cosmos/iavl) in python, and provides a cli tool to inspect the cosmos-sdk application db, can be used for debugging production issues, or doing fast rollback.

The cli tool can be run as nix flake on the fly, there are two exposed app, the `iavl-cli`(the default one) is for rocksdb db backend, the `iavl-cli-leveldb` is for goleveldb backend.

```
$ nix run github:crypto-com/python-iavl/$GIT_REF#iavl-cli -- --help
Usage: iavl [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  commit-infos    print latest version and commit infos of rootmulti store
  diff-fastnode   compare fast node index with latest iavl tree version,...
  fast-node       print the content of a fast node
  fast-rollback   A quick and dirty way to rollback chain state
  metadata        print storage version and latest version of iavl stores
  node            print the content of a node
  range-fastnode  iterate fast node index
  range-iavl      iterate iavl tree
  root-hash       print root hashes of iavl stores
```
