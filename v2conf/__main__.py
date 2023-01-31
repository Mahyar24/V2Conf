#! /usr/bin/env python3.9

"""
This package helps you to create the configuration file for V2Ray automatically
and find the best outbounds and change the routing rules periodically based on
outbounds performances.
Dependencies:
    - requests
    - aiohttp
    - [jdatetime] (optional) (if you want to configure the Jalali date-time for logging)

Check out this Gist for detecting abnormal user traffic:
https://gist.github.com/Mahyar24/d712a30a35576e5b8584c562e15e550c

Compatible with Python 3.9+
GitHub: https://github.com/Mahyar24/V2Conf
Mahyar@Mahyar24.com, Sun Nov 13 2022
"""

import argparse
import asyncio
import logging
import os
import re
import subprocess
import textwrap
import time
from pathlib import Path
from time import struct_time
from zoneinfo import ZoneInfo

from .configs import make_conf, write_conf
from .health import rank_outbounds

__version__ = "0.0.8"
__author__ = "Mahyar Mahdavi"
__email__ = "Mahyar@Mahyar24.com"
__license__ = "GPLv3"
__url__ = "https://GitHub.com/Mahyar24/V2Conf"
__pypi__ = "https://PyPI.org/project/V2Conf"


def check_requirements() -> None:
    """
    Assert if user is running the script with root privileges.
    """
    assert os.getuid() == 0, "You must have super user permissions to run this program."


def tehran_time(*_, **__) -> time.struct_time:
    """
    Struct_time for Jalali date-time.
    """

    try:
        import jdatetime  # type: ignore
    except ImportError as err:
        raise ImportError(
            "Please install `jdatetime` module to use Jalali date-time for logging"
        ) from err

    tehran_dt = jdatetime.datetime.now(tz=ZoneInfo("Asia/Tehran"))
    return struct_time(
        (
            tehran_dt.year,
            tehran_dt.month,
            tehran_dt.day,
            tehran_dt.hour,
            tehran_dt.minute,
            tehran_dt.second,
            tehran_dt.weekday(),
            tehran_dt.yday(),
            1,
        )
    )


def make_logger(args: argparse.Namespace) -> logging.Logger:
    """
    Make a logger and return it.
    """
    logging.raiseExceptions = False
    if args.jalali:
        logging.Formatter.converter = tehran_time

    logger = logging.getLogger(os.path.basename(__file__))
    logger.setLevel(logging.INFO)

    handler_formatter = logging.Formatter(
        "%(asctime)s:%(levelname)s:%(message)s.", datefmt="%Y-%m-%d %H:%M:%S"
    )

    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(handler_formatter)
    logger.addHandler(stdout_handler)

    if not args.quiet:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(handler_formatter)
        logger.addHandler(file_handler)

    return logger


def validate_url(text: str) -> bool:
    """
    Check if the text is a valid http(s) URL.
    """
    pattern = re.compile(
        r"^(http)s?://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    return bool(re.match(pattern, text))


def checking_args(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """
    Check the passed arguments and return the parsed arguments.
    """
    args = parser.parse_args()
    if not validate_url(args.website):
        parser.error("The website you entered is not a valid URL.")
    if not args.path_conf_dir.is_dir():
        parser.error(
            f"The directory you entered {args.path_conf_dir!r} is not a valid directory."
        )
    return args


def parsing_args() -> argparse.Namespace:
    """
    Parsing the passed arguments, read help (-h, --help) for further information.
    """
    parser = argparse.ArgumentParser(
        epilog=textwrap.dedent(
            """
            Written by: Mahyar Mahdavi <Mahyar@Mahyar24.com>.
            License: GNU GPLv3.
            Source Code: <https://github.com/mahyar24/V2Conf>.
            Reporting Bugs and PRs are welcomed. :)
            """
        )
    )
    group = parser.add_mutually_exclusive_group()

    parser.add_argument(
        "path_conf_dir",
        nargs="?",
        default=Path.cwd(),
        type=Path,
        help="Select configuration directory, default is $PWD.",
    )

    parser.add_argument(
        "-c",
        "--config-file",
        default=Path("/usr/local/etc/v2ray/config.json"),
        type=Path,
        help="Select configuration file, default is '/usr/local/etc/v2ray/config.json'.",
    )

    parser.add_argument(
        "--country-code",
        help="Exclude a country from the list of IPs to be routed; "
        "default is 'IR'. (ISO 3166-1 alpha-2)",
        type=lambda x: x.upper(),
        default="IR",
    )

    parser.add_argument(
        "--no-geoip",
        help="Instead of using V2Ray GeoIP database, "
        "downloading IPs from 'ripe.net' (more recent IPs but may slow V2Ray)",
        action="store_true",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        help="Set the timeout for checking the health of proxies, default is 15 seconds.",
        type=int,
        default=15,
    )

    parser.add_argument(
        "-w",
        "--website",
        help="Set the website to be used for checking the health of proxies, "
        "default is 'https://facebook.com'",
        default="https://facebook.com",
    )

    parser.add_argument(
        "-n",
        "--num-of-tries",
        help="Set the number of tries for checking the health of proxies, default is 10.",
        type=int,
        default=10,
    )

    parser.add_argument(
        "-s",
        "--sleep-time",
        help="Set the sleep time between each checkup, default is 1,800s. (in seconds)",
        type=int,
        default=1_800,
    )

    parser.add_argument(
        "-l",
        "--log-level",
        help="Set the V2Ray log level, default is 'warning'.",
        choices=["debug", "info", "warning", "error", "none"],
        default="warning",
    )

    group.add_argument(
        "-q",
        "--quiet",
        help="No log file (V2Conf). (printing to stdout anyway)",
        action="store_true",
    )

    group.add_argument(
        "--log-file",
        help="Path for V2Conf log file. default is '$PWD/V2Conf.log'",
        default=Path.cwd() / "V2Conf.log",
        type=Path,
    )

    parser.add_argument(
        "--jalali", help="Use Jalali datetime for V2Conf logging", action="store_true"
    )

    parser.add_argument(
        "-v",
        "--version",
        help="Show version and exit.",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return checking_args(parser)


def restart_v2ray(logger: logging.Logger) -> None:
    """
    Restart V2Ray service. (systemctl)
    When `check=True` is passed to `run`, `CalledProcessError` is raised if the
    exit code was non-zero.
    """
    subprocess.run(["systemctl", "restart", "v2ray"], check=True)
    logger.warning("V2Ray is restarted")


def main() -> None:
    """
    Main function.
    """
    check_requirements()

    args = parsing_args()
    logger = make_logger(args)

    # At the first run, we will make a naive configuration file.
    # and all inbounds will route to a randomly selected outbound.
    conf = make_conf(args, logger)
    write_conf(args.config_file, conf)
    logger.info("Naive configuration file is written")

    restart_v2ray(logger)

    time.sleep(30)

    while True:
        # Ranking outbound performances.
        ranked_outbounds = asyncio.run(
            rank_outbounds(
                args,
                logger,
                http_inbounds=[
                    inbound
                    for inbound in conf["inbounds"]
                    if inbound["tag"].startswith("inbound-http-test-")
                ],
            )
        )

        # Make the new configuration file and set all inbounds to the best inbound.
        conf = make_conf(args, logger, ranked_outbounds[0])
        # Write the new configuration file.
        write_conf(args.config_file, conf)
        logger.info("Configuration file is written")
        # Restarting to apply the new configuration file.
        restart_v2ray(logger)
        # Sleeping until the next checkup.
        logger.info(f"Sleeping for {args.sleep_time:,} seconds")
        time.sleep(args.sleep_time)


if __name__ == "__main__":
    main()
