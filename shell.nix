{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.rustup
    pkgs.gcc
  ];
}
