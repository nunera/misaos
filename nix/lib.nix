{ getTool }:
let
  # These constructors serialize declarations, not roots or executable host systems.
  # The Rust consumer remains the authority for schema and semantic validation.
  mkRecord = domain: { pkgs, declaration, name ? "misa-${domain}-plan" }:
    let
      schemaVersion = "misa.${domain}/v1";
      record =
        if !(builtins.isAttrs declaration) then
          throw "Misa ${domain}: declaration must be an attribute set"
        else if declaration ? schemaVersion && declaration.schemaVersion != schemaVersion then
          throw "Misa ${domain}: declaration has a different authority discriminator"
        else declaration // { inherit schemaVersion; };
      source = pkgs.writeText "${name}-declaration.json" (builtins.toJSON record);
      tool = getTool pkgs.stdenv.hostPlatform.system;
    in pkgs.runCommand name {
      nativeBuildInputs = [ tool ];
      passthru = {
        declaration = record;
        validationScope = "schema-and-semantics-only";
      };
    } ''
      mkdir -p "$out"
      misa-plan canonicalize ${source} --expect ${domain} > "$out/${domain}.json"
      misa-plan validate "$out/${domain}.json" --expect ${domain} > "$out/receipt.json"
      misa-plan digest "$out/${domain}.json" --expect ${domain} > "$out/digest.txt"
    '';
in {
  inherit mkRecord;
  mkStrataPlan = mkRecord "strata";
  mkHostPlan = mkRecord "plan";
}
