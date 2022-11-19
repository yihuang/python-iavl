{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/master";
    flake-utils.url = "github:numtide/flake-utils";
    rocksdb-src = {
      url = "github:facebook/rocksdb/v6.29.5";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, rocksdb-src }:
    let
      overrides = { poetry2nix, rocksdb, leveldb, lib }: poetry2nix.overrides.withDefaults
        (lib.composeManyExtensions [
          (self: super:
            let
              buildSystems = {
                rocksdb = [ "setuptools" "cython" "pkgconfig" ];
                cprotobuf = [ "setuptools" ];
                pyzstd = [ "setuptools" ];
                pyroaring = [ "setuptools" ];
                roaring64 = [ "poetry" ];
              };
            in
            lib.mapAttrs
              (attr: systems: super.${attr}.overridePythonAttrs
                (old: {
                  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ map (a: self.${a}) systems;
                }))
              buildSystems
          )
          (self: super: {
            rocksdb = super.rocksdb.overridePythonAttrs (old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ rocksdb ];
            });
            plyvel = super.plyvel.overridePythonAttrs (old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ leveldb ];
            });
          })
        ]);
      iavl-env = { callPackage, poetry2nix, groups ? [ "rocksdb" ] }:
        poetry2nix.mkPoetryEnv {
          projectDir = ./.;
          overrides = callPackage overrides { };
          inherit groups;
        };
      iavl-cli = { poetry2nix, callPackage, groups ? [ "rocksdb" ] }:
        poetry2nix.mkPoetryApplication {
          projectDir = ./.;
          overrides = callPackage overrides { };
          inherit groups;
        };
    in
    (flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              self.overlay
            ];
            config = { };
          };
        in
        rec {
          packages = {
            iavl-env = pkgs.callPackage iavl-env { };
            iavl-env-leveldb = pkgs.callPackage iavl-env { groups = [ "leveldb" ]; };
            iavl-cli = pkgs.callPackage iavl-cli { };
            iavl-cli-leveldb = pkgs.callPackage iavl-cli { groups = [ "leveldb" ]; };
          };
          defaultPackage = packages.iavl-cli;
          apps = {
            default = {
              type = "app";
              program = "${packages.iavl-cli}/bin/iavl";
            };
            iavl-cli-leveldb = {
              type = "app";
              program = "${packages.iavl-cli-leveldb}/bin/iavl";
            };
            archive-cli = {
              type = "app";
              program = "${packages.iavl-cli}/bin/archive";
            };
          };
          devShells = {
            default = pkgs.mkShell {
              buildInputs = [ packages.iavl-env ];
            };
            leveldb = pkgs.mkShell {
              buildInputs = [ packages.iavl-env-leveldb ];
            };
          };
        }
      )
    ) // {
      overlay = final: prev: {
        rocksdb = prev.rocksdb.overrideAttrs (old: rec {
          pname = "rocksdb";
          version = "6.29.5";
          src = rocksdb-src;
        });
      };
    };
}
