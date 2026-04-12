{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        sopsy = pkgs.python313Packages.buildPythonPackage rec {
          pname = "sopsy";
          version = "1.2.1";
          pyproject = true;

          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-IVmoL2/uELfim2iOSgvcGlDpbo2iNX/0b5dVSv8JkPE=";
          };
          propagatedBuildInputs = with pkgs.python313Packages; [ pyyaml ];
          build-system = [ pkgs.python313Packages.hatchling ];
          doCheck = false;
        };

        pythonEnv = pkgs.python313.withPackages (
          ps: with ps; [
            pykeepass
            sopsy
          ]
        );

        app = pkgs.writeShellApplication {
          name = "wayland-keepass-autotype";
          runtimeInputs = with pkgs; [
            wtype
            rofi
            sops
            pythonEnv
          ];
          text = ''
            python ${./read_keepass.py} "$@"
          '';
        };

      in
      {
        packages.default = app;

        apps.default = {
          type = "app";
          program = "${app}/bin/wayland-keepass-autotype";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ pythonEnv ];
        };
      }
    );
}
