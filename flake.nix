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
      overrides = { poetry2nix, rocksdb, lib }: poetry2nix.overrides.withDefaults
        (lib.composeManyExtensions [
          (self: super:
            let
              buildSystems = {
                rocksdb = [ "setuptools" "cython" "pkgconfig" ];
                cprotobuf = [ "setuptools" ];
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
          })
        ]);
      iavl-env = { callPackage, poetry2nix }:
        poetry2nix.mkPoetryEnv {
          projectDir = ./.;
          overrides = callPackage overrides { };
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
            iavl-cli = pkgs.writeShellScriptBin "iavl" ''
              ${packages.iavl-env}/bin/iavl $@
            '';
          };
          defaultPackage = packages.iavl-cli;
          apps = {
            default = {
              type = "app";
              program = "${packages.iavl-cli}/bin/iavl";
            };
          };
          devShell = pkgs.mkShell {
            buildInputs = [ packages.iavl-env ];
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
