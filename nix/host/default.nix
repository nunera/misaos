# Evaluate a Misa full-host configuration: `misa.*` modules only, no NixOS modules.
{ pkgs, misaHost, misaTool, planLib }:
modules:
(pkgs.lib.evalModules {
  modules = [ ./options.nix ./base.nix ./testing.nix ./build.nix ] ++ modules;
  specialArgs = { inherit pkgs misaHost misaTool planLib; };
}).config.misa.build
