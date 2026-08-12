{
  description = "termius-export - decrypt and convert Termius local data offline";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs:
        let
          py = pkgs.python3Packages;

          # Chromium layers its own key encoding and V8 structured-clone value format
          # on top of LevelDB. These two CCL forensics packages implement that parsing -
          # the one part of this project that is not reasonably reimplementable.
          # Both are GitHub-only (not on PyPI), hence the pinned revisions.
          ccl-simplesnappy = py.buildPythonPackage {
            pname = "ccl_simplesnappy";
            version = "0.4";
            format = "pyproject";
            src = pkgs.fetchFromGitHub {
              owner = "cclgroupltd";
              repo = "ccl_simplesnappy";
              rev = "3d085230baa8c46cf2090ebba29bf6e8eab31087";
              hash = "sha256-ssQIZyhrhttqaQjdk/DOiRwqBiKqCf9QiDN2rJ6E7+c=";
            };
            nativeBuildInputs = [ py.setuptools py.wheel ];
            doCheck = false;
            pythonImportsCheck = [ "ccl_simplesnappy" ];
          };

          ccl-chromium-reader = py.buildPythonPackage {
            pname = "ccl_chromium_reader";
            version = "0.3.18";
            format = "pyproject";
            src = pkgs.fetchFromGitHub {
              owner = "cclgroupltd";
              repo = "ccl_chromium_reader";
              rev = "ef840de30221c4d65bc96d2f4d9057e9ef2f526d";
              hash = "sha256-BRplu68GTnXmMkxfX/Pbb8IFPAzotbGCknzrZJvu8s8=";
            };
            nativeBuildInputs = [ py.setuptools py.wheel ];
            propagatedBuildInputs = [ ccl-simplesnappy py.brotli py.zstd ];
            # Upstream pins zstd==1.5.7.2; nixpkgs ships 1.5.7.3. Patch-level only.
            pythonRelaxDeps = [ "zstd" "Brotli" ];
            doCheck = false;
            pythonImportsCheck = [ "ccl_chromium_reader" ];
          };

          pythonEnv = pkgs.python3.withPackages (ps: [
            ps.pynacl # XSalsa20-Poly1305, for Termius secretbox fields
            ccl-chromium-reader
          ]);
        in
        {
          inherit ccl-simplesnappy ccl-chromium-reader pythonEnv;

          default = pkgs.writeShellApplication {
            name = "termius-export";
            runtimeInputs = [ pythonEnv ];
            text = ''exec python -m termius_export "$@"'';
          };
        });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            self.packages.${pkgs.stdenv.hostPlatform.system}.pythonEnv
            pkgs.ruff # lint + format
            pkgs.openssh # ssh -G, used to verify the generated sshconfig
            pkgs.git
            pkgs.jq
          ];

          shellHook = ''
            export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            # Output contains plaintext private keys; create everything privately.
            umask 077
            # stderr, not stdout: `nix develop --command ... --json` must stay parseable
            echo "termius-export dev shell: $(python --version)" >&2
          '';
        };
      });
    };
}
