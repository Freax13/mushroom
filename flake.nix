{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/f771eb401a46846c1aebd20552521b233dd7e18b";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, flake-utils, naersk, rust-overlay, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = (import nixpkgs) {
          inherit system overlays;
        };


  toolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
  extensions = [ "rust-src" ];
  targets = [ "x86_64-unknown-none" ];
  };

        naersk' = pkgs.callPackage naersk {
          cargo=toolchain;
          rustc=toolchain;
        };

      in rec {
        # For `nix build` & `nix run`:
        defaultPackage = naersk'.buildPackage {
          src = ./.; 
          root = ./tee;
          preBuild = "pwd && ls && cd tee/kernel";
          # copySources = ["../common"];
          # copySourcesFrom=./tee;
        #   additionalCargoLock = ./tee/Cargo.lock;
singleStep=true;

        #   override = old: {
        #     preBuild = ''
        #       find /build
        #       exit 1
        #     '';
        #   };
        };

        # For `nix develop` (optional, can be skipped):
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ rustc cargo ];
        };
      }
    );
}