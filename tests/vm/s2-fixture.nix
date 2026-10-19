# Fixtures for the S2 second-ecosystem test: a real, pinned, Void-musl-derived OCI
# image beside the S1 Debian-derived image, and the merged lockset that lets one
# strata plan bind both roots.
#
# Trust story, unchanged from S1:
# * The official `ghcr.io/void-linux/void-musl` manifest is pinned by digest (as in
#   examples/void-musl.lock.json) and carries NO publisher signature. It is only the
#   unmodified base of the derived image and the unsigned negative scenario.
# * The same independent fixture publisher key as S1 (never the operator's admission
#   key, never a Void or Debian key) signs the derived image's manifest binding.
{ pkgs, misa, s1 }:

let
  inherit (pkgs) lib;

  # Official linux/amd64 `ghcr.io/void-linux/void-musl:20261001R1` manifest.
  baseManifest = {
    digest = "sha256:1a0bc3529a34744744a92a44d15bb850eef872767eabdc5d2e81b810b4f9e2a2";
    size = 673;
  };

  baseLayout = pkgs.runCommand "misa-s2-void-musl-base-oci"
    {
      nativeBuildInputs = [ pkgs.skopeo ];
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";
      outputHash = "sha256-EBghe1onvC2n4GYge04AIeNZZvbsGl+hveGTYO7CcYM=";
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    } ''
    export HOME="$TMPDIR"
    skopeo --insecure-policy copy --override-os linux --override-arch amd64 \
      docker://ghcr.io/void-linux/void-musl@${baseManifest.digest} oci:"$TMPDIR/download":latest
    mkdir -p "$out/blobs/sha256"
    cp "$TMPDIR"/download/blobs/sha256/* "$out/blobs/sha256/"
    echo "${lib.removePrefix "sha256:" baseManifest.digest}  $out/blobs/sha256/${lib.removePrefix "sha256:" baseManifest.digest}" | sha256sum --check --quiet
    printf '%s' '{"imageLayoutVersion":"1.0.0"}' > "$out/oci-layout"
    printf '%s' '{"manifests":[{"digest":"${baseManifest.digest}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":${toString baseManifest.size}}],"schemaVersion":2}' > "$out/index.json"
  '';

  images = pkgs.runCommand "misa-s2-images" {
    nativeBuildInputs = [ pkgs.python3 ];
    PYTHONPATH = "${s1.ociFixture}";
  } ''
    python3 ${./s2-image.py} \
      --base-layout ${baseLayout} \
      --debian-base-layout ${s1.baseLayout} \
      --probe ${./s1-probe.sh} \
      --source example.org/misa/void-musl \
      --out "$out"
  '';

  # One lockset for one plan: the unchanged S1 release-1 Debian entry plus both Void
  # entries, merged by the real CLI. It needs its own local approval.
  lockset = pkgs.runCommand "misa-s2-lockset" { nativeBuildInputs = [ misa ]; } ''
    mkdir -p "$out"
    misa strata merge-locks \
      --lock ${s1.locks.debian-desktop-v1} \
      --lock ${images}/void-musl-v1/lock.json \
      --lock ${images}/void-musl-upstream/lock.json \
      --output "$out/lock.json"
  '';

  statements = pkgs.runCommand "misa-s2-publisher-statements" { nativeBuildInputs = [ misa ]; } ''
    mkdir -p "$out" secrets
    install -m600 ${s1.keys}/publisher/secret.json secrets/publisher.json
    misa strata publisher-sign \
      --lock ${images}/void-musl-v1/lock.json \
      --name void-musl-v1 \
      --key-id ${s1.publisherKeyId} \
      --secret-key secrets/publisher.json \
      --output "$out/void-v1.json"
  '';

  summary = builtins.fromJSON (builtins.readFile "${images}/summary.json");
in
{
  inherit baseLayout images lockset statements summary;
  layouts = {
    debian-desktop-v1 = s1.layouts.debian-desktop-v1;
    void-musl-v1 = "${images}/void-musl-v1/layout";
    void-musl-upstream = "${baseLayout}";
  };
  locks = {
    debian-desktop-v1 = s1.locks.debian-desktop-v1;
    lockset = "${lockset}/lock.json";
  };
}
