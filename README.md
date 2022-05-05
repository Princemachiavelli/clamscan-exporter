# clamscan-exporter
Provide metrics of clamscan results. Stream clamscan results with netcat over TCP to exporter. 


## metrics 

metrics are provided on /metrics

Example metrics output:
```
# HELP clamscan_files The number of scanned files
# TYPE clamscan_files gauge
clamscan_files{code="Empty file",path="",virus=""} 21
clamscan_files{code="Excluded",path="",virus=""} 8
clamscan_files{code="FOUND",path="/tmp/test/eicar.com",virus="Win.Test.EICAR_HDB-1"} 1
clamscan_files{code="FOUND",path="/var/log/test.10.log",virus="testvirus"} 1
clamscan_files{code="OK",path="",virus=""} 1195
clamscan_files{code="Symbolic link",path="",virus=""} 251

```

Only the FOUND code will have details about path and virus. The rest are summarized over total count. 

## usage from clamscan

```
$ clamscan-exporter  --help
Usage of clamscan-exporter:
  -http-port string
    	port to listen tcp connections on (default "8080")
  -tcp-port string
    	port to listen tcp connections on (default "9000")
```

We use a systemd service with the following to pipe results to exporter:
```
clamscan -r --stdout --no-summary --cross-fs=no /tmp | nc 127.0.0.1 9000
```
