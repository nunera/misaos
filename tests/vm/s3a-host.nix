# The S3a VM host: one headless Misa host on Dinit, evaluated once per borrowed stage 1.
# Disk identities are fixed so the root selector and the image builder agree.
{ stage1, testing ? true, extraModules ? [ ] }:
{ lib, ... }:
let
  fileDigest = path: "sha256:" + builtins.hashFile "sha256" path;
in
{
  imports = [ ./s3a-conformance.nix ] ++ extraModules;
  misa = {
    hostId = "s3a";
    machineId = "5a3a000000000000000000000000c0de";
    inputs = {
      flakeLockDigest = fileDigest ../../flake.lock;
      flakeSourceDigest = fileDigest ./s3a-host.nix;
      # The host binds no foreign roots; this is the digest of the canonical empty lockset.
      foreignLockDigest = fileDigest ./s3a-empty.lock.json;
      misaLibraryDigest = fileDigest ../../nix/host/build.nix;
    };
    boot = {
      inherit stage1;
      root.selector = { kind = "partuuid"; value = "5a3a0001-0000-4000-8000-00000000c0de"; };
    };
    testing.backdoor = testing;
  };
}
