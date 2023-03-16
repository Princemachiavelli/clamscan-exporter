{ config, lib, pkgs, prometheus-clamscan-exporter, ... }: with lib;
let
  cfg = config.services.prometheus-clamscan-exporter;
  exportPkg = prometheus-clamscan-exporter;
in
{
  options.services.prometheus-clamscan-exporter = {
    enable = mkOption {
      type = types.bool;
      default = false;
    };
    clamavAddress = {
      type = types.string;
      default = "/run/clamav/clamd.ctl";
    };
    clamavPort = {
      type = types.port;
      default = 3310;
    };
    clamavNetworkType = {
      type = types.string; 
      default = "unix";
      descrption = ''
        Network mode to use, typically tcp or unix (socket).
      '';
    };
    scanSchedule = mkOption {
      type = types.string;
      default = "daily";
      description = ''
        How open to do full clamav scan of local disks ('/').
      '';
    };
  };
  config = mkIf cfg.enable (mkMerge [
    {
      systemd.services."prometheus-clamscan-exporter" = {
        description = "ClamAV Scanner Prometheus Exporter";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          PrivateTmp = true;
          PrivateDevices = true;
          ExecStart = "${exportPkg}/bin/clamav-prometheus-exporter -clamav-address ${cfg.clamavAddress} -clamav-port ${cfg.clamavPort} -network ${cfg.clamavNetworkType}";
          # clamAV socket is world RW.
          DynamicUser = true;
        };
      };
    }
    {
      systemd.services."clamscan-schedule" = {
        serviceConfig = {
          # Limit to local mount points only, use clamdscan or just clamscan?
          ExecStart = ''
            ${pkgs.clamav}/bin/clamdscan -r --stdout --no-summary --fdpass  / | ${pkgs.netcat}/bin/nc 127.0.0.0 9000 
          '';
          # Since we use --fdpass then this should work.
          DynamicUser = true;
          PrivateTmp = true;
          PrivateDevices = true;
        };
        startAt = cfg.scanSchedule;
      };
    }
  ]); 
}
