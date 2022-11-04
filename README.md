Default app is for rocksdb backend, use `nix run github:yihuang/python-iavl#iavl-cli-leveldb` for leveldb backend.

```
$ nix run github:yihuang/python-iavl -- --help
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
