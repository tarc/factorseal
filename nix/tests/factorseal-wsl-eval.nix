{ pkgs, module }:

let
  lib = pkgs.lib;
  package = pkgs.writeShellScriptBin "factorseal" ''printf '%s\n' "$@"'';
  evaluate =
    extra:
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        module
        {
          services.factorseal = {
            enable = true;
            mode = "wsl";
            inherit package;
          };
          system.stateVersion = "26.05";
        }
        extra
      ];
    }).config;
  # A WSL distro has no TPM: the vault lives on Windows.
  evaluated = evaluate { security.tpm2.enable = false; };
  failing =
    config:
    map (assertion: assertion.message) (
      lib.filter (
        assertion: !assertion.assertion && lib.hasInfix "services.factorseal" assertion.message
      ) config.assertions
    );
  withGnomeKeyring = evaluate {
    security.tpm2.enable = false;
    services.gnome.gnome-keyring.enable = true;
  };
  activation = lib.findFirst (
    package: package.name == "factorseal-wsl-keyring-activation"
  ) (throw "WSL keyring activation missing from D-Bus packages") evaluated.services.dbus.packages;
  unit = evaluated.systemd.user.services.factorseal-wsl-keyring;
in
assert failing evaluated == [ ];
assert lib.any (lib.hasInfix "gnome-keyring") (failing withGnomeKeyring);
assert !evaluated.security.tpm2.enable;
assert !(builtins.hasAttr "factorseal" evaluated.systemd.user.services);
assert !(builtins.hasAttr "dev.factorseal.Desktop" evaluated.systemd.user.services);
assert builtins.elem package evaluated.environment.systemPackages;
assert unit.serviceConfig.Type == "dbus";
assert unit.serviceConfig.BusName == "org.freedesktop.secrets";
assert unit.serviceConfig.ExecStart == "${package}/bin/factorseal wsl-keyring";
assert unit.environment.DBUS_SESSION_BUS_ADDRESS == "unix:path=%t/bus";
# Hardened like the agent, but WSL interop needs AF_VSOCK to run the broker.
assert unit.serviceConfig.MemoryDenyWriteExecute;
assert builtins.elem "AF_VSOCK" unit.serviceConfig.RestrictAddressFamilies;
pkgs.runCommand "factorseal-wsl-module-evaluation" { } ''
  service=${activation}/share/dbus-1/services/org.freedesktop.secrets.service
  grep -Fx "Name=org.freedesktop.secrets" "$service"
  grep -Fx "SystemdService=factorseal-wsl-keyring.service" "$service"
  activation=$(sed -n 's/^Exec=//p' "$service")
  test "$activation" = "${package}/bin/factorseal wsl-keyring"
  touch "$out"
''
