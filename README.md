>  Only support rocksdb right now.

```
$ nix run github:yihuang/python-iavl -- --help
Usage: iavl [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  commit-infos    print latest version and commit infos of rootmulti store
  fast-node       print the content of a fast node
  latest-version  print latest versions of iavl stores
  metadata        print storage version of iavl stores
  node            print the content of a node
  root-hash       print root hashes of iavl stores
```
