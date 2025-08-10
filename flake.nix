{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils = {
      url = "github:numtide/flake-utils";
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

  outputs =
    {
      self,
      flake-utils,
      naersk,
      rust-overlay,
      nixpkgs,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = (import nixpkgs) {
          inherit system overlays;
        };
        toolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          extensions = [ "rust-src" ];
          targets = [
            "x86_64-unknown-none"
            "x86_64-unknown-linux-gnu"
          ];
        };
        naersk' = pkgs.callPackage naersk {
          cargo = toolchain;
          rustc = toolchain;
        };
        fs = pkgs.lib.fileset;
        teeAttrs = {
          src = fs.toSource {
            root = ./.;
            fileset = (
              fs.unions [
                ./Makefile
                ./config.mk
                ./common
                ./tee
              ]
            );
          };
          PROFILE = "release";
          root = ./tee;
          singleStep = true;
          additionalCargoLock = "${toolchain}/lib/rustlib/src/rust/library/Cargo.lock";
        };

      in
      rec {
        defaultPackage = mushroom;
        mushroom = cli.overrideAttrs (p: {
          name = "mushroom";
          DEFAULT_PATH_KERNEL = "${placeholder "out"}/share/kernel";
          DEFAULT_PATH_SUPERVISOR_SNP = "${placeholder "out"}/share/supervisor-snp";
          DEFAULT_PATH_SUPERVISOR_TDX = "${placeholder "out"}/share/supervisor-tdx";
          installPhase =
            p.installPhase
            + ''
              mkdir -p $out/share
              ln -s ${kernel} $out/share/kernel
              ln -s ${supervisor-snp} $out/share/supervisor-snp
              ln -s ${supervisor-tdx} $out/share/supervisor-tdx
            '';
        });

        cli = naersk'.buildPackage {
          name = "cli";
          version = (builtins.fromTOML (builtins.readFile ./host/mushroom/Cargo.toml)).package.version;
          src = fs.toSource {
            root = ./.;
            fileset = (
              fs.unions [
                ./Makefile
                ./config.mk
                ./common
                ./host
              ]
            );
          };
          preBuild = "cd host/mushroom";
          root = ./host;
          singleStep = true;
        };
        kernel = naersk'.buildPackage (
          {
            name = "kernel";
            version = (builtins.fromTOML (builtins.readFile ./tee/kernel/Cargo.toml)).package.version;
            buildPhase = "make kernel";
            installPhase = "cp tee/target/x86_64-unknown-none/kernel-release/kernel $out";
          }
          // teeAttrs
        );
        supervisor-snp = naersk'.buildPackage (
          {
            name = "supervisor-snp";
            version = (builtins.fromTOML (builtins.readFile ./tee/supervisor-snp/Cargo.toml)).package.version;
            buildPhase = "make supervisor-snp";
            installPhase = "cp tee/target/supervisor/supervisor-release/supervisor-snp $out";
          }
          // teeAttrs
        );
        supervisor-tdx = naersk'.buildPackage (
          {
            name = "supervisor-tdx";
            version = (builtins.fromTOML (builtins.readFile ./tee/supervisor-tdx/Cargo.toml)).package.version;
            buildPhase = "make supervisor-tdx";
            installPhase = "cp tee/target/supervisor/supervisor-release/supervisor-tdx $out";
          }
          // teeAttrs
        );

        formatter = nixpkgs.legacyPackages.${system}.nixfmt-tree;
      }
    );
}
