# MisaOS S1 stock-NixOS strata module.
#
# Renders declared exports of a validated misa.strata/v1 plan as per-user
# CLI commands and desktop entries that invoke the real launcher:
#
#   misa run --plan <plan>/strata.json --store <store> --export <id> \
#     --publisher-keyring <keyring> [-- args...]
#
# Invariants kept by this module:
# - The stock host is unchanged apart from installing the misa package and
#   adding per-user profile entries. No boot, init, account, service,
#   tmpfiles or activation-script changes; nothing runs as root; there is
#   no GC and no per-launch privilege.
# - The retained store stays caller-owned: the module never creates,
#   imports into, seals or garbage-collects it. Importing remains an
#   explicit unprivileged `misa strata import` performed by the owning user
#   with their own admission materials; local operator admission is never
#   rendered as publisher trust.
# - Publisher trust is external and pinned: launch passes this module's
#   read-only Nix-store keyring (one closed misa.publisher-key/v1 record
#   per explicitly configured key), and evaluation fails closed when the
#   plan references a publisher key the operator has not configured. There
#   is no fallback.
{ config, lib, pkgs, ... }:

let
  cfg = config.misa.strata;

  strataSchema = "misa.strata/v1";

  # The declaration used to render exports must be the same immutable plan
  # that the launcher validates. Never pair a mutable runtime file with an
  # unrelated evaluation-time declaration.
  planFileOf = plan: "${plan}/strata.json";

  planRecordOf = instance: icfg:
    let record = icfg.plan.declaration or { };
    in lib.throwIfNot
      (icfg.plan ? validationScope
        && icfg.plan.validationScope == "schema-and-semantics-only"
        && record ? schemaVersion
        && record.schemaVersion == strataSchema)
      "misa.strata instance '${instance}': plan must be a mkStrataPlan output with a misa.strata/v1 declaration"
      record;

  asciiIdOk = s: builtins.stringLength s <= 64 && builtins.match "[a-z][a-z0-9.-]*" s != null;
  desktopIdOk = s: builtins.stringLength s <= 255 && builtins.match "[A-Za-z][A-Za-z0-9._-]*[.]desktop" s != null;
  noControlChars = s: builtins.match "[^\n\r\t]*" s != null;

  exportMap = record: builtins.listToAttrs (map (e: { name = e.id; value = e; }) record.exports);
  rootMap = record: builtins.listToAttrs (map (r: { name = r.digest; value = r; }) record.roots);

  # Publisher keyIds the plan binds to the roots behind `ids`, via
  # export.root -> roots[].sourceLockKey -> trust.imagePublishers.
  requiredPublisherKeyIds = record: ids:
    let
      exports = exportMap record;
      roots = rootMap record;
      imagePublishers = record.trust.imagePublishers or { };
      keyIdsFor = id:
        let
          export = exports.${id};
          root = roots.${export.root} or null;
          policy = if root == null then null else imagePublishers.${root.sourceLockKey} or null;
          structural =
            if root == null then
              "export '${id}' references root '${export.root}' not declared by the plan"
            else if policy == null then
              "plan has no trust.imagePublishers entry for sourceLockKey '${root.sourceLockKey}' (root of export '${id}')"
            else null;
        in
        lib.throwIf (structural != null) "misa.strata: ${structural}" (map (key: key.keyId) policy);
    in
    lib.unique (lib.concatMap keyIdsFor (lib.filter (id: exports ? ${id}) ids));

  # The launcher fails closed when trust.imagePublishers disagrees with the
  # pinned keyring record, so reject that disagreement at evaluation too.
  # Returns "<sourceLockKey>/<keyId>" labels for every disagreeing entry
  # among configured keys (unconfigured keys are reported separately).
  disagreeingPublisherKeys = record: ids: keys:
    let
      exports = exportMap record;
      roots = rootMap record;
      imagePublishers = record.trust.imagePublishers or { };
      entriesFor = id:
        let root = roots.${exports.${id}.root} or null;
        in if root == null then [ ] else
          map (entry: { inherit (root) sourceLockKey; inherit entry; }) (imagePublishers.${root.sourceLockKey} or [ ]);
      agrees = entry: key:
        entry.status == key.status
        && entry.validFrom == key.validFrom
        && entry.validUntil == key.validUntil
        && (entry.revokedNotBefore or null) == key.revokedNotBefore
        && (entry.successorOf or null) == key.successorOf;
      bad = lib.filter
        (e: keys ? ${e.entry.keyId} && !agrees e.entry keys.${e.entry.keyId})
        (lib.concatMap entriesFor (lib.filter (id: exports ? ${id}) ids));
    in
    lib.unique (map (e: "${e.sourceLockKey}/${e.entry.keyId}") bad);

  # Read-only, pinned keyring: one closed misa.publisher-key/v1 record per
  # explicitly configured key, file name `<keyId>.json` (the ASCII alias
  # the plan's trust.imagePublishers references). The launcher cross-checks
  # plan windows/status against these records and fails closed.
  publisherKeyring = instance: keys:
    pkgs.runCommand "misa-strata-${instance}-publisher-keyring" { }
      (''
        mkdir -p "$out"
      '' + lib.concatMapStrings (keyId:
        let
          key = keys.${keyId};
          body =
            { schemaVersion = "misa.publisher-key/v1"; inherit keyId; alg = "ed25519"; inherit (key) publicKey validFrom validUntil status; }
            // lib.optionalAttrs (key.revokedNotBefore != null) { inherit (key) revokedNotBefore; }
            // lib.optionalAttrs (key.successorOf != null) { inherit (key) successorOf; };
        in
        ''
          printf '%s\n' '${builtins.toJSON body}' > "$out/${keyId}.json"
        '') (lib.attrNames keys));

  launcherArgv = { misa, planFile, store, exportId, keyring }: [
    "${misa}/bin/misa"
    "run"
    "--plan" planFile
    "--store" store
    "--export" exportId
    "--publisher-keyring" "${keyring}"
  ];

  # Unprivileged per-user command. The owner guard keeps another local
  # account from probing a store it cannot own; `misa run` still verifies
  # the retained manifest itself before executing anything.
  exportWrapper = { instance, name, user, argv }:
    let
      q = lib.escapeShellArg;
      inner = lib.concatStringsSep " " (map q argv);
    in
    pkgs.writeShellScriptBin name ''
      set -eu
      if [ "$(id -un)" != ${q user} ]; then
        echo "misa strata instance ${q instance} is scoped to user ${q user}; refusing to run as $(id -un)." >&2
        exit 1
      fi
      if [ "$#" -gt 0 ]; then
        exec ${inner} -- "$@"
      fi
      exec ${inner}
    '';

  # Desktop Entry Specification argument quoting. This module emits no
  # %-field codes, so a literal percent is doubled; an argument containing
  # a reserved character (or empty) is quoted whole, with backslash escapes
  # inside quotes for backslash, double quote, dollar and backtick.
  desktopArg = arg:
    let
      doubled = lib.replaceStrings [ "%" ] [ "%%" ] arg;
      reserved = [ " " "\t" "\n" "\"" "'" "\\" ">" "<" "~" "|" "&" ";" "$" "*" "?" "#" "(" ")" "`" ];
      needsQuote = doubled == "" || lib.any (c: lib.hasInfix c doubled) reserved;
      escaped = lib.replaceStrings [ "\\" "\"" "$" "`" ] [ "\\\\" "\\\"" "\\$" "\\`" ] doubled;
    in
    if needsQuote then "\"" + escaped + "\"" else doubled;

  desktopExecLine = argv: lib.concatStringsSep " " (map desktopArg argv);

  # Desktop entries launch the real launcher directly, unprivileged, in the
  # owner's session. Plan-declared icons live inside the retained root, not
  # on the host, so no Icon key is emitted.
  desktopEntry = { instance, misa, export, execLine }:
    let
      lines = [
        "[Desktop Entry]"
        "Type=Application"
        "Version=1.5"
        "Name=${export.name}"
        "Exec=${execLine}"
        "TryExec=${misa}/bin/misa"
        "Terminal=false"
        "DBusActivatable=false"
        "X-MisaStrataInstance=${instance}"
        "X-MisaStrataExport=${export.id}"
        "X-MisaStrataRoot=${export.root}"
      ] ++ lib.optional (export.desktop.mime != [ ])
        "MimeType=${lib.concatStringsSep ";" export.desktop.mime};";
    in
    pkgs.writeTextDir "share/applications/${export.desktop.id}"
      (lib.concatStringsSep "\n" lines + "\n");

  instancePieces = instance: icfg:
    let
      record = planRecordOf instance icfg;
      exports = exportMap record;
      ids = lib.unique (icfg.cliExports ++ icfg.desktopExports);
      known = lib.filter (id: exports ? ${id}) ids;
      unknownIds = lib.subtractLists known ids;
      noDesktop = lib.filter (id: exports ? ${id} && !(exports.${id} ? desktop)) icfg.desktopExports;
      badNames = lib.filter (id: exports ? ${id} && !asciiIdOk exports.${id}.name) ids;
      badDesktopIds =
        lib.filter (id: exports ? ${id} && exports.${id} ? desktop && !desktopIdOk exports.${id}.desktop.id) icfg.desktopExports;
      unqualifiedDbus = lib.filter (id: exports ? ${id} && exports.${id} ? desktop && exports.${id}.desktop.dbusName != null) icfg.desktopExports;
      neededKeys = requiredPublisherKeyIds record known;
      missingKeys = lib.subtractLists (lib.attrNames icfg.publisherKeys) neededKeys;
      disagreeing = disagreeingPublisherKeys record known icfg.publisherKeys;
      badKeyIds = lib.filter (k: !asciiIdOk k) (lib.attrNames icfg.publisherKeys);
      badSuccessors = lib.filter
        (k: icfg.publisherKeys.${k}.successorOf != null && !asciiIdOk icfg.publisherKeys.${k}.successorOf)
        (lib.attrNames icfg.publisherKeys);
      errors =
        lib.optional (unknownIds != [ ]) "unknown export ids: ${toString unknownIds}"
        ++ lib.optional (noDesktop != [ ]) "desktopExports list exports without a desktop record: ${toString noDesktop}"
        ++ lib.optional (badNames != [ ]) "export names not usable as command names: ${toString badNames}"
        ++ lib.optional (badDesktopIds != [ ]) "desktop ids not usable as desktop file names: ${toString badDesktopIds}"
        ++ lib.optional (unqualifiedDbus != [ ]) "D-Bus activation is not qualified for desktop exports: ${toString unqualifiedDbus}"
        ++ lib.optional (badKeyIds != [ ]) "publisherKeys keyIds not usable as file names: ${toString badKeyIds}"
        ++ lib.optional (badSuccessors != [ ]) "publisherKeys successorOf values not usable as identifiers: ${toString badSuccessors}"
        ++ lib.optional (missingKeys != [ ])
          "publisher keys required by the plan but not configured in publisherKeys (no broad fallback): ${toString missingKeys}"
        ++ lib.optional (disagreeing != [ ])
          "trust.imagePublishers disagrees with publisherKeys (status/window/revokedNotBefore/successorOf must be identical): ${toString disagreeing}";
      keyring = publisherKeyring instance icfg.publisherKeys;
      argvOf = id: launcherArgv {
        misa = cfg.package;
        planFile = planFileOf icfg.plan;
        store = icfg.store;
        exportId = id;
        inherit keyring;
      };
      # Every exported id also installs its wrapper command: a desktop
      # entry's launcher invocation is a CLI command by construction.
      pieces = map
        (id:
          let
            export = exports.${id};
            wantsDesktop = lib.elem id icfg.desktopExports;
          in
          {
            inherit (export) name;
            desktopId = if wantsDesktop then export.desktop.id else null;
            wrapper = exportWrapper { inherit instance; name = export.name; user = icfg.user; argv = argvOf id; };
            desktop = if wantsDesktop then
              desktopEntry { inherit instance; export = exports.${id}; misa = cfg.package; execLine = desktopExecLine (argvOf id); }
            else null;
          })
        ids;
    in
    lib.throwIf (errors != [ ])
      "misa.strata instance '${instance}': ${lib.concatStringsSep "; " errors}"
      { inherit (icfg) user store; inherit instance pieces; };

  grouped = lib.groupBy (entry: entry.user)
    (lib.mapAttrsToList (instance: icfg: instancePieces instance icfg) cfg.instances);

  renderUser = user: entries:
    let
      users = config.users.users;
      home = if users ? ${user} then users.${user}.home else "/nonexistent";
      uid = if users ? ${user} then users.${user}.uid else null;
      # Per-option module merging keeps this read free of cycles with the
      # packages entries this module adds in `config` below: only the
      # home/uid/isNormalUser suboptions are forced here, never `packages`.
      declared = users ? ${user} &&
        (users.${user}.isNormalUser || users.${user}.isSystemUser || uid != null);
      storeErrors = lib.concatMap
        ({ instance, store, ... }:
          let
            shape =
              lib.optional (!(lib.hasPrefix "/" store)) "instance '${instance}': store '${store}' is not an absolute path"
              ++ lib.optional (!noControlChars store) "instance '${instance}': store must not contain tab or line breaks";
          in
          shape ++ lib.optional (shape == [ ] && !(lib.hasPrefix "${home}/" store))
            "instance '${instance}': store '${store}' is not inside the home directory of user '${user}' ('${home}'); the retained store stays owned and scoped to that user")
        entries;
      pieces = lib.concatMap (entry: entry.pieces) entries;
      names = map (p: p.name) pieces;
      desktopIds = lib.filter (x: x != null) (map (p: p.desktopId) pieces);
      duplicates = xs: lib.filter (x: lib.length (lib.filter (y: y == x) xs) > 1) (lib.unique xs);
      errors =
        lib.optional (!declared)
          "user '${user}' is not a declared account (set isNormalUser, isSystemUser or an explicit uid in users.users); this module never creates accounts"
        ++ lib.optional (declared && user == "root") "user 'root' is not allowed: launches must stay unprivileged"
        ++ lib.optional (declared && uid == 0) "user '${user}' has uid 0: launches must stay unprivileged"
        ++ storeErrors
        ++ lib.optional (duplicates names != [ ])
          "command name collisions between instances for this user: ${toString (duplicates names)}"
        ++ lib.optional (duplicates desktopIds != [ ])
          "desktop id collisions between instances for this user: ${toString (duplicates desktopIds)}";
    in
    lib.throwIf (errors != [ ])
      "misa.strata (user '${user}'): ${lib.concatStringsSep "; " errors}"
      (pkgs.buildEnv {
        name = "misa-strata-${user}-exports";
        paths = map (p: p.wrapper) pieces ++ lib.filter (p: p != null) (map (p: p.desktop) pieces);
      });

  active = cfg.instances != { };
  packageError =
    lib.optional (active && !(lib.hasPrefix "misa-cli" (cfg.package.name or "")))
      "misa.strata.package must be the real misa CLI package (expected a 'misa-cli-...' derivation, got '${cfg.package.name or "unnamed"}')";
  userEnvs =
    lib.throwIf (packageError != [ ]) (lib.head packageError)
      (lib.mapAttrs renderUser grouped);
in
{
  options.misa.strata = {
    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The misa CLI package to install and launch through. Must be the
        real pinned build (pname `misa-cli`, with pinned skopeo, umoci and
        bubblewrap); evaluation fails for any other derivation. The module
        never imports or launches anything on its own.
      '';
    };

    instances = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule ({ ... }: {
        options = {
          plan = lib.mkOption {
            type = lib.types.package;
            description = ''
              A mkStrataPlan output. Its declaration renders exports at
              evaluation, while its build validates and canonicalizes the
              immutable plan the launcher reads.
            '';
          };
          user = lib.mkOption {
            type = lib.types.str;
            description = ''
              Owner of the retained store and of the rendered exports. Must
              be an existing declared account (isNormalUser, isSystemUser or
              an explicit uid); this module never creates accounts. Root and
              uid 0 are rejected because launches must stay unprivileged.
            '';
          };
          store = lib.mkOption {
            type = lib.types.str;
            description = ''
              Absolute path of the caller-owned retained store for this
              instance, inside the owning user's home directory. The module
              never creates, seals or garbage-collects it; the user imports
              into it explicitly with `misa strata import`. Until a root is
              imported, launches fail closed.
            '';
          };
          cliExports = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = ''
              Export ids to render as per-user commands named by each
              export's `name` (its host CLI name). Colliding names across
              instances for one user fail evaluation.
            '';
          };
          desktopExports = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = ''
              Export ids to render as per-user desktop entries (the export
              must declare a `desktop` record; its `id` is the entry file
              name). The entry launches the real launcher directly and
              unprivileged; its wrapper command is installed as well.
              Colliding desktop ids or command names across instances for
              one user fail evaluation.
            '';
          };
          publisherKeys = lib.mkOption {
            type = lib.types.attrsOf (lib.types.submodule ({ ... }: {
              options = {
                publicKey = lib.mkOption {
                  type = lib.types.strMatching "[0-9a-f]{64}";
                  description = "Ed25519 verifying key bytes, 64 lowercase hex characters.";
                };
                validFrom = lib.mkOption {
                  type = lib.types.ints.unsigned;
                  description = "Validity window start, UTC Unix seconds.";
                };
                validUntil = lib.mkOption {
                  type = lib.types.ints.unsigned;
                  description = "Validity window end, UTC Unix seconds.";
                };
                status = lib.mkOption {
                  type = lib.types.enum [ "active" "retiring" "revoked" ];
                  default = "active";
                  description = "Key status. The launcher cross-checks it and the window against the plan and fails closed on disagreement.";
                };
                revokedNotBefore = lib.mkOption {
                  type = lib.types.nullOr lib.types.ints.unsigned;
                  default = null;
                  description = "Optional revocation floor, UTC Unix seconds.";
                };
                successorOf = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = "Optional keyId this key rotates.";
                };
              };
            }));
            default = { };
            description = ''
              Explicit publisher key registry for this instance, keyed by
              the ASCII alias keyId the plan's trust.imagePublishers
              references. Rendered as a pinned read-only keyring directory
              passed to `misa run --publisher-keyring`: one closed
              misa.publisher-key/v1 record per key at `<keyId>.json`.
              Evaluation fails closed when the plan references a keyId that
              is not configured here; local operator admission keys are not
              publisher trust and must not be listed.
            '';
          };
        };
      }));
      default = { };
      description = ''
        Strata instances to render for the stock host. Each instance wires
        declared exports of one validated plan to one explicitly selected
        user-owned retained store. The host's kernel, PID 1, boot and
        accounts are untouched.
      '';
    };
  };

  config = {
    environment.systemPackages = lib.mkIf active [ cfg.package ];

    users.users = lib.mkIf active (lib.mapAttrs (user: env: { packages = [ env ]; }) userEnvs);
  };
}
