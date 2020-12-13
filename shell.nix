{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    buildInputs = with pkgs; [
      # libavutil-dev libavformat-dev libavfilter-dev libavdevice-dev
      mscgen
      pkg-config
      latest.rustChannels.stable.rust
      # profiling
      cargo-flamegraph
    ];
}
