{
  description = "MisaOS: strict plans and standalone, publisher-qualified OCI strata on stock NixOS";

  # Explicit updates only; this revision is from the stable nixos-26.05 branch.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/6fcc160353f63555b560f25588925133c8f61f2a";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      planLib = import ./nix/lib.nix {
        getTool = system: self.packages.${system}.misa;
      };
      strataFixtureDeclaration = builtins.fromJSON (builtins.readFile ./fixtures/strata.json);
      # S1 module-test plan: the synthetic fixture export with a desktop
      # record and a distinct host CLI name, for exercising desktop
      # rendering. Still synthetic: no artifact qualification is claimed.
      strataDesktopFixtureDeclaration = strataFixtureDeclaration // {
        exports = [
          (builtins.head strataFixtureDeclaration.exports // {
            name = "hello-desktop";
            desktop = {
              id = "misa-strata-desktop-fixture.desktop";
              entryDigest = "sha256:" + builtins.hashString "sha256" "misa-strata-desktop-fixture";
              icons = [ ];
              mime = [ "application/vnd.misa.strata-fixture" ];
              dbusName = null;
            };
          })
        ];
      };
    in {
      lib = {
        inherit (planLib) mkStrataPlan mkHostPlan;
      };

      nixosModules.strata = import ./nix/strata-module.nix;

      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in rec {
          misa = pkgs.callPackage ./nix/package.nix { };
          default = misa;
          misa-host = pkgs.callPackage ./nix/host-package.nix { };
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
          strata-desktop-fixture = planLib.mkStrataPlan {
            inherit pkgs;
            name = "misa-s1-strata-desktop-fixture";
            declaration = strataDesktopFixtureDeclaration;
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
          inherit (packages) strata-fixture strata-desktop-fixture plan-fixture generation-fixture wire-fixture;
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
          strata-module = import ./nix/strata-tests.nix {
            inherit nixpkgs pkgs system;
            strataModule = self.nixosModules.strata;
            misa = packages.misa;
            strataFixture = packages.strata-fixture;
            strataDesktopFixture = packages.strata-desktop-fixture;
            planFixture = packages.plan-fixture;
          };
        } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Stock-NixOS CLI/desktop, upgrade-survival and offline-relaunch VM gate.
          s1 = import ./tests/vm/s1.nix {
            inherit pkgs;
            misa = packages.misa;
            strataModule = self.nixosModules.strata;
          };
          # Second ecosystem: Void musl beside Debian in one merged lockset and plan.
          s2 = import ./tests/vm/s2.nix {
            inherit pkgs;
            misa = packages.misa;
            strataModule = self.nixosModules.strata;
          };
          # First owned boot: UEFI, borrowed stage 1, misa-handoff, Dinit as PID 1.
          s3a = import ./tests/vm/s3a.nix {
            inherit pkgs planLib;
            misa = packages.misa;
            misaHost = packages.misa-host;
          };
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
