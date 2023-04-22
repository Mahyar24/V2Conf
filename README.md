# V2Conf

V2Conf helps you build V2Ray Config file automatically and evaluate and change config rules based on outbounds performances.
## Installation & Running

```bash
sudo apt-get install pipx && pipx install --python python3.9 v2conf;
sudo $(which v2conf) /home/ubuntu/confs -n 10 --no-geoip --country-code 'IR' --jalali --log-file /home/ubuntu/v2conf.log 
```

## Recommended Usage
```bash
sudo $(which v2conf) /home/ubuntu/confs -n 10 -s 900 --timeout-penalty 15 --ema 8,2 --no-geoip --country-code 'IR' --log-level error --jalali -w "https://dl-cdn.alpinelinux.org/alpine/v3.17/releases/x86/alpine-minirootfs-3.17.1-x86.tar.gz" --log-file /home/ubuntu/v2conf.log 
```
With these flags and settings, V2Conf will download the selected file every 15 minutes (900 / 60 = 15) 10 times for each outbound.\
V2Conf will print logs in Jalali date times in `/home/ubuntu/v2conf.log` and `stdout` simultaneously and it will exclude IPs for Iran. (useful for domestic Iranian VPSs) \
`--timeout-penalty 15` makes the program to consider a failed test as a test with 15 seconds latency and based on exponential moving average of last `8` evaluations (past 2 hours) and weighting more importance on recent evaluations (`2` times for every new evaluation) choose the best outbound and route all data within that.\
`--log-level error` indicates that **V2Ray** log level will be `error`.

## Details

V2Conf expects a directory with this structure from you:
```bash
confs/
├── inbounds  # an "inbounds" directory
│   └── main_entry.json
├── outbounds  # an "outbounds" directory
│   ├── blocked.json
│   ├── direct.json
│   ├── trojan_h2.json
│   ├── trojan_ws_cloudflare.json
│   ├── vless_h2.json
│   └── vless_ws_cloudflare.json
└── rules  # a "rules" directory
    ├── ir.json
    └── private.json
```
where each inbound, outbound or rule should be saved as a json file (*.json).
e.g. `main_entry.json`:
```json
{
  "port": 6060,
  "protocol": "trojan",
  "settings": {
    "clients":
    ...
```
and **all configs must have a tag!**
P.S.: Thanks to [Tushar](https://github.com/Mahyar24/V2Conf/pull/2) V2Conf now supports JSON5 format for configs.


## Usage
```
$ v2conf --help
usage: v2conf [-h] [-c CONFIG_FILE] [--country-code COUNTRY_CODE] [--no-geoip] [-t TIMEOUT] [-w WEBSITE] [-n NUM_OF_TRIES] [--timeout-penalty TIMEOUT_PENALTY] [--ema EMA] [-s SLEEP_TIME]
                   [-l {debug,info,warning,error,none}] [-q | --log-file LOG_FILE] [--jalali] [-v]
                   [path_conf_dir]

positional arguments:
  path_conf_dir         Select configuration directory, default is $PWD.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Select configuration file, default is '/usr/local/etc/v2ray/config.json'.
  --country-code COUNTRY_CODE
                        Exclude a country from the list of IPs to be routed; default is 'IR'. (ISO 3166-1 alpha-2)
  --no-geoip            Instead of using V2Ray GeoIP database, downloading IPs from 'ripe.net' (more recent IPs but may slow V2Ray)
  -t TIMEOUT, --timeout TIMEOUT
                        Set the timeout for checking the health of proxies, default is 15 seconds.
  -w WEBSITE, --website WEBSITE
                        Set the website to be used for checking the health of proxies, default is 'https://facebook.com'.
  -n NUM_OF_TRIES, --num-of-tries NUM_OF_TRIES
                        Set the number of tries for checking the health of proxies, default is 10.
  --timeout-penalty TIMEOUT_PENALTY
                        Converting timeouts to latency by this factor (in seconds), DISABLED by default.
  --ema EMA             Instead of choosing OutBound based on latest evaluation, rank based on exponential moving average of last Nth tests and smoothing variable. (e.g. --ema 10,2.5), DISABLED by default.
  -s SLEEP_TIME, --sleep-time SLEEP_TIME
                        Set the sleep time between each checkup, default is 1,800s. (in seconds)
  -l {debug,info,warning,error,none}, --log-level {debug,info,warning,error,none}
                        Set the V2Ray log level, default is 'warning'.
  -q, --quiet           No log file (V2Conf). (printing to stdout anyway)
  --log-file LOG_FILE   Path for V2Conf log file. default is '$PWD/V2Conf.log'
  --jalali              Use Jalali datetime for V2Conf logging
  -v, --version         Show version and exit.

Written by: Mahyar Mahdavi <Mahyar@Mahyar24.com>. License: GNU GPLv3. Source Code: <https://github.com/mahyar24/V2Conf>. Reporting Bugs and PRs are welcomed. :)

```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Contact me: <OSS@Mahyar24.com> :)

## License
[GNU GPLv3 ](https://choosealicense.com/licenses/gpl-3.0/)
