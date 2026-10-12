{
  description = "MisaOS: strict plans and locally approved, retained OCI roots";

  # Explicit updates only; this revision is from the stable nixos-26.05 branch.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/6fcc160353f63555b560f25588925133c8f61f2a";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      planLib = import ./nix/lib.nix {
        getTool = system: self.packages.${system}.misa;
      };
    in {
      lib = {
        inherit (planLib) mkStrataPlan mkHostPlan;
      };

      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in rec {
          misa = pkgs.callPackage ./nix/package.nix { };
          default = misa;
          strata-fixture = planLib.mkStrataPlan {
            inherit pkgs;
            name = "misa-s0-strata-fixture";
            declaration = builtins.fromJSON (builtins.readFile ./fixtures/strata.json);
          };
          plan-fixture = planLib.mkHostPlan {
            inherit pkgs;
            name = "misa-s0-plan-fixture";
            declaration = builtins.fromJSON (builtins.readFile ./fixtures/plan.json);
          };
          generation-fixture = planLib.mkRecord "generation" {
            inherit pkgs;
            name = "misa-s0-generation-fixture";
            declaration = builtins.fromJSON (builtins.readFile ./fixtures/generation.json);
          };
          wire-fixture = pkgs.writeTextDir "wire.json" (builtins.toJSON (
            builtins.map
              (vector: {
                inherit (vector) name;
                source = builtins.toJSON (builtins.fromJSON vector.source);
              })
              (builtins.filter (vector: vector ? canonicalHex)
                (builtins.fromJSON (builtins.readFile ./fixtures/wire.json)).vectors)
          ));
        });

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          packages = self.packages.${system};
        in {
          inherit (packages) strata-fixture plan-fixture generation-fixture wire-fixture;
          s0 = pkgs.runCommand "misa-s0-conformance" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            python3 ${./nix/s0.py} \
              --tool ${packages.misa}/bin/misa-plan \
              --fixtures ${./fixtures} \
              --nix-wire ${packages.wire-fixture}/wire.json \
              --strata ${packages.strata-fixture}/strata.json \
              --plan ${packages.plan-fixture}/plan.json \
              --generation ${packages.generation-fixture}/generation.json
            mkdir -p "$out"
            printf '%s\n' 'S0 schema and identity conformance only; no VM or activation.' > "$out/scope"
          '';
        });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ cargo rustc rustfmt clippy python3 skopeo umoci bubblewrap ];
            MISA_SKOPEO = "${pkgs.skopeo}/bin/skopeo";
            MISA_UMOCI = "${pkgs.umoci}/bin/umoci";
            MISA_BWRAP = "${pkgs.bubblewrap}/bin/bwrap";
            MISA_TEST_SKOPEO = "${pkgs.skopeo}/bin/skopeo";
            MISA_TEST_UMOCI = "${pkgs.umoci}/bin/umoci";
            MISA_TEST_BWRAP = "${pkgs.bubblewrap}/bin/bwrap";
          };
        });
    };
}
