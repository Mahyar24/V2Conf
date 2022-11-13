# V2Conf

V2Conf helps you build V2Ray Config file automatically and evaluate and change config rules based on outbounds performances.
## Installation & Running

```bash
sudo apt-get install pipx && pipx install v2conf;
sudo ./$(which v2conf) /home/ubuntu/confs -n 20 --jalali --log-file /home/ubuntu/v2conf.log 
```

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
and **all files must have a tag!**


## Usage
```bash
$ v2conf --help
usage: __main__.py [-h] [-c CONFIG_FILE] [--country-code COUNTRY_CODE] [-t TIMEOUT] [-w WEBSITE] [-n NUM_OF_TRIES] [-s SLEEP_TIME]
                   [-l {debug,info,warning,error,none}] [-q | --log-file LOG_FILE] [--jalali] [-v]
                   [path_conf_dir]

positional arguments:
  path_conf_dir         Select configuration directory, default is $PWD.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Select configuration file, default is /usr/local/etc/v2ray/config.json.
  --country-code COUNTRY_CODE
                        Exclude a country from the list of IPs to be routed; default is 'IR'. (ISO 3166-1 alpha-2)
  -t TIMEOUT, --timeout TIMEOUT
                        Set the timeout for checking the health of proxies, default is 15 seconds.
  -w WEBSITE, --website WEBSITE
                        Set the website to be used for checking the health of proxies, default is https://facebook.com
  -n NUM_OF_TRIES, --num-of-tries NUM_OF_TRIES
                        Set the number of tries for checking the health of proxies, default is 10.
  -s SLEEP_TIME, --sleep-time SLEEP_TIME
                        Set the sleep time between each checkup, default is 30 minutes. (in seconds)
  -l {debug,info,warning,error,none}, --log-level {debug,info,warning,error,none}
                        Set the log level, default is warning.
  -q, --quiet           No log file. (printing to stdout anyway)
  --log-file LOG_FILE   Path for V2Conf log file.
  --jalali              Use Jalali date and time.
  -v, --version         Show version and exit.

Written by: Mahyar Mahdavi <Mahyar@Mahyar24.com>. License: GNU GPLv3. Source Code: <https://github.com/mahyar24/V2Conf>. Reporting
Bugs and PRs are welcomed. :)
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Contact me: <OSS@Mahyar24.com> :)

## License
[GNU GPLv3 ](https://choosealicense.com/licenses/gpl-3.0/)
