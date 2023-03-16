{ lib, buildGoModule }:

buildGoModule rec {
  pname = "prometheus-clamscan-exporter";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  vendorSha256 = "sha256-M9Oqp14kUVC5+pMOJhHpMfr6M0g+YKxhZA9laU6qNOQ=";
  proxyVendor = true;
}
