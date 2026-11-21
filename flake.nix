{
  description = "Autonomous Software Factory orchestrator (sf) for herdr-core coding environments";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python312;
          software-factory = python.pkgs.buildPythonApplication {
            pname = "software-factory";
            version = "0.1.0";
            pyproject = true;
            src = ./.;

            build-system = [ python.pkgs.setuptools ];

            makeWrapperArgs = [
              "--prefix"
              "PATH"
              ":"
              (pkgs.lib.makeBinPath [
                pkgs.bash
                pkgs.coreutils
                pkgs.git
                pkgs.gh
                pkgs.jq
                pkgs.openssh
              ])
            ];

            doCheck = true;
            nativeCheckInputs = [ pkgs.git ];
            checkPhase = ''
              runHook preCheck
              ${python.interpreter} -m unittest discover -s tests -v
              runHook postCheck
            '';

            postInstall = ''
              install -Dm644 schemas/signal.v1.schema.json "$out/share/software-factory/schemas/signal.v1.schema.json"
              install -Dm644 schemas/review-verdict.v1.schema.json "$out/share/software-factory/schemas/review-verdict.v1.schema.json"
            '';

            meta = with pkgs.lib; {
              description = "Autonomous Software Factory CLI orchestrating herdr-core agents";
              mainProgram = "sf";
              platforms = platforms.unix;
            };
          };
        in
        {
          default = software-factory;
          inherit software-factory;
        }
      );

      checks = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.software-factory;
          formatting = pkgs.runCommand "check-nixfmt" { nativeBuildInputs = [ pkgs.nixfmt ]; } ''
            nixfmt --check ${./flake.nix}
            touch $out
          '';
        }
      );

      devShells = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.python312
              pkgs.git
              pkgs.gh
              pkgs.jq
              pkgs.nixfmt
            ];
          };
        }
      );

      formatter = eachSystem (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
