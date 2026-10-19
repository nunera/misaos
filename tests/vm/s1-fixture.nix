# Fixtures for the S1 stock-NixOS test: a real, pinned, Debian-derived OCI image,
# independent signing/admission keys and the publisher statements.
#
# Trust story, kept honest:
# * The official Docker `library/debian` manifest is pinned by digest and carries
#   NO publisher signature. It is only ever used (a) as the unmodified base of the
#   derived image and (b) as the negative "unsigned upstream" scenario.
# * The derived image is built here, from the pinned base plus SHA-256-pinned
#   Debian packages. A separate `fixture publisher` key (never the operator's
#   admission key, never a Debian key) signs its manifest binding.
# * The local operator's admission key is a third key, generated independently.
{ pkgs, misa }:

let
  inherit (pkgs) lib;

  debsLock = builtins.fromJSON (builtins.readFile ./s1-debs.lock.json);

  # Official linux/amd64 `docker.io/library/debian` bookworm manifest, as pinned
  # by examples/debian-bookworm.lock.json; package snapshots are locked below.
  baseManifest = {
    digest = "sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91";
    size = 1021;
  };

  publisherKeyId = "misa-fixture";

  # Fetched by manifest digest, then reassembled as a canonical OCI layout so the
  # fixed-output hash depends only on the content-addressed blobs.
  baseLayout = pkgs.runCommand "misa-s1-debian-bookworm-base-oci"
    {
      nativeBuildInputs = [ pkgs.skopeo ];
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";
      outputHash = "sha256-q8m1Mh0vAiX8FA+fd4BZvQlcK/w1lcrKDBzlOAAM66I=";
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    } ''
    export HOME="$TMPDIR"
    skopeo --insecure-policy copy --override-os linux --override-arch amd64 \
      docker://docker.io/library/debian@${baseManifest.digest} oci:"$TMPDIR/download":latest
    mkdir -p "$out/blobs/sha256"
    cp "$TMPDIR"/download/blobs/sha256/* "$out/blobs/sha256/"
    echo "${lib.removePrefix "sha256:" baseManifest.digest}  $out/blobs/sha256/${lib.removePrefix "sha256:" baseManifest.digest}" | sha256sum --check --quiet
    printf '%s' '{"imageLayoutVersion":"1.0.0"}' > "$out/oci-layout"
    printf '%s' '{"manifests":[{"digest":"${baseManifest.digest}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":${toString baseManifest.size}}],"schemaVersion":2}' > "$out/index.json"
  '';

  debsDir = pkgs.linkFarm "misa-s1-debs" (map
    (package: {
      name = baseNameOf package.filename;
      path = pkgs.fetchurl {
        name = lib.strings.sanitizeDerivationName (baseNameOf package.filename);
        url = debsLock.urlPrefix + package.filename;
        sha256 = package.sha256;
      };
    })
    debsLock.packages);

  # Shared with the plan: the entry digest the plan records is this text's digest.
  desktopText = ''
    [Desktop Entry]
    Type=Application
    Name=misa-s1-xclock
    Exec=xclock -title misa-s1-gui
  '';
  desktopEntry = pkgs.writeText "misa-s1-xclock.desktop" desktopText;

  # Shared deterministic OCI writer, also used by the S2 Void fixture.
  ociFixture = pkgs.writeTextDir "ocifixture.py" (builtins.readFile ./ocifixture.py);

  images = pkgs.runCommand "misa-s1-images" {
    nativeBuildInputs = [ pkgs.python3 ];
    PYTHONPATH = "${ociFixture}";
  } ''
    python3 ${./s1-image.py} \
      --base-layout ${baseLayout} \
      --debs-lock ${./s1-debs.lock.json} \
      --debs-dir ${debsDir} \
      --probe ${./s1-probe.sh} \
      --desktop-entry ${desktopEntry} \
      --source example.org/misa/debian-desktop \
      --out "$out"
  '';

  # Three independent Ed25519 identities: the local operator (admission), the
  # fixture publisher, and a rogue key used only to prove impersonation fails.
  keys = pkgs.runCommand "misa-s1-keys" { nativeBuildInputs = [ misa ]; } ''
    mkdir -p "$out"
    for identity in operator publisher rogue; do
      misa trust keygen --directory "$out/$identity" > /dev/null
    done
  '';

  statements = pkgs.runCommand "misa-s1-publisher-statements" { nativeBuildInputs = [ misa ]; } ''
    mkdir -p "$out" secrets
    install -m600 ${keys}/publisher/secret.json secrets/publisher.json
    install -m600 ${keys}/rogue/secret.json secrets/rogue.json
    for release in v1 v2; do
      misa strata publisher-sign \
        --lock ${images}/debian-desktop-$release/lock.json \
        --name debian-desktop-$release \
        --key-id ${publisherKeyId} \
        --secret-key secrets/publisher.json \
        --output "$out/$release.json"
    done
    # Same alias, wrong key: an impersonation the keyring must reject.
    misa strata publisher-sign \
      --lock ${images}/debian-desktop-v1/lock.json \
      --name debian-desktop-v1 \
      --key-id ${publisherKeyId} \
      --secret-key secrets/rogue.json \
      --output "$out/rogue-v1.json"
  '';

  summary = builtins.fromJSON (builtins.readFile "${images}/summary.json");
in
{
  inherit baseLayout images keys statements summary desktopEntry publisherKeyId ociFixture;
  publisherPublicKey = (builtins.fromJSON (builtins.readFile "${keys}/publisher/public.json")).publicKey;
  desktopEntryDigest = "sha256:" + builtins.hashString "sha256" desktopText;
  # Layouts imported with `--from-layout`; the upstream layout is the unmodified Docker image.
  layouts = {
    debian-upstream = "${baseLayout}";
    debian-desktop-v1 = "${images}/debian-desktop-v1/layout";
    debian-desktop-v2 = "${images}/debian-desktop-v2/layout";
  };
  locks = {
    debian-upstream = "${images}/debian-upstream/lock.json";
    debian-desktop-v1 = "${images}/debian-desktop-v1/lock.json";
    debian-desktop-v2 = "${images}/debian-desktop-v2/lock.json";
  };
}
