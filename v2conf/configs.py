#! /usr/bin/env python3.9

"""
This module is used for reading and writing configuration files.

GitHub: https://github.com/Mahyar24/V2Conf
Mahyar@Mahyar24.com, Sun Nov 13 2022
"""


import argparse
import json
import logging
import secrets
import socket
from contextlib import closing
from pathlib import Path
from typing import Optional

from .exclude import make_ip_rule


def find_n_unused_port(num: int) -> list[int]:
    """
    Find n unique unused port and return them as a list.
    """
    ports: set[int] = set()
    while len(ports) < num:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.bind(("", 0))
            port = sock.getsockname()[1]
            ports.add(port)

    return list(ports)


def make_http_inbounds(outbound_tags: list[str], logger: logging.Logger) -> list[dict]:
    """
    For every outbound, create a http inbound for performing the outbound.
    """
    http_inbounds = []

    ports = find_n_unused_port(len(outbound_tags))

    for port, outbound_tag in zip(ports, outbound_tags):
        http_inbounds.append(
            {
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "accounts": [
                    {
                        "user": secrets.token_urlsafe(16),
                        "pass": secrets.token_urlsafe(16),
                    }
                ],
                "tag": f"inbound-http-test-{outbound_tag}",
            }
        )
        logger.info(f"HTTP proxy created '127.0.0.1:{port}' for {outbound_tag!r}")

    return http_inbounds


def read_inbounds(path: Path) -> dict[str, dict]:
    """
    Reading inbounds from the path.
    """
    inbounds_path = path / "inbounds"

    inbounds = {}
    for config in inbounds_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = json.load(file)
            try:
                inbounds[data["tag"]] = data
            except KeyError as err:
                raise KeyError(f"Tag not found in {config.name}") from err
            else:
                if data["tag"].startswith("inbound-test-http-"):
                    raise ValueError(
                        f"'inbound-test-http-*' is reserved for internal use. "
                        f"change the tag in {config.name}"
                    )

    return inbounds


def read_outbounds(path: Path) -> dict[str, dict]:
    """
    Reading outbounds from the path. at least one freedom outbound is required.
    """
    outbounds_path = path / "outbounds"

    outbounds = {}

    check_freedom = False
    for config in outbounds_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = json.load(file)
            try:
                outbounds[data["tag"]] = data
            except KeyError as err:
                raise KeyError(f"Tag not found in {config.name}") from err

            if data["protocol"] == "freedom":
                check_freedom = True

    if not check_freedom:
        raise ValueError("Freedom outbound not found!")

    return outbounds


def read_rules(path: Path) -> dict[str, dict]:
    """
    Reading rules from the path.
    """
    rules_path = path / "rules"

    rules = {}
    for config in rules_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = json.load(file)
            try:
                rules[data["tag"]] = data
            except KeyError as err:
                raise KeyError(f"Tag not found in {config.name}") from err

    return rules


def make_rules(
    path: Path,
    logger: logging.Logger,
    *,
    county_code: str,
    http_inbounds: list[dict],
    inbound_tags: list[str],
    freedom_outbound_tag: str,
    outbound: Optional[str] = None,
) -> list[dict]:
    """
    Make rules for the configuration file.
    """

    # Rules for excluding domestic IPs.
    ip_rules = make_ip_rule(county_code, freedom_outbound_tag, logger)
    logger.info(f"Excluding {len(ip_rules['ip'])} IPs for {county_code!r}")

    # Rules from rules directory
    rules = list(read_rules(path).values())
    logger.info(f"Read {len(rules)} rules")

    rules += [ip_rules]

    # Rules for routing http proxies to their corresponding outbounds.
    for http_inbound in http_inbounds:
        rules.append(
            {
                "inboundTag": [http_inbound["tag"]],
                "outboundTag": http_inbound["tag"].split("-")[1],
                "type": "field",
            }
        )

    # If nothing is specified, route all traffic to freedom outbound. (cold start)
    # Otherwise, route all traffic to the specified (best) outbound.
    outbound_tag = outbound or freedom_outbound_tag
    logger.info(f"Using {outbound_tag!r} as default outbound")
    rules.append(
        {
            "inboundTag": inbound_tags,
            "outboundTag": outbound_tag,
            "type": "field",
        }
    )

    return rules


def make_conf(
    args: argparse.Namespace,
    logger: logging.Logger,
    outbound_tag: Optional[str] = None,
) -> dict:
    """
    Make a new configuration file.
    """
    inbounds = read_inbounds(args.path_conf_dir)
    logger.info(f"Read {len(inbounds)} inbounds")

    outbounds = read_outbounds(args.path_conf_dir)

    # We should only make http inbounds for the outbounds that are not freedom or blackhole.
    vpn_outbounds = [
        k for k, v in outbounds.items() if v["protocol"] not in ("freedom", "blackhole")
    ]
    logger.info(f"Read {len(outbounds)} outbounds, {len(vpn_outbounds)} vpn outbounds")

    # find tag of freedom outbound, using when making first naive config file.
    freedom = [k for k, v in outbounds.items() if v["protocol"] == "freedom"][0]

    http_inbounds = make_http_inbounds(vpn_outbounds, logger)

    rules = make_rules(
        args.path_conf_dir,
        logger,
        county_code=args.country_code,
        http_inbounds=http_inbounds,
        inbound_tags=list(inbounds.keys()),
        freedom_outbound_tag=freedom,
        outbound=outbound_tag,
    )

    return {
        "log": {"loglevel": args.log_level},
        "inbounds": list(inbounds.values()) + http_inbounds,
        "outbounds": list(outbounds.values()),
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def write_conf(path: Path, conf: dict) -> None:
    """
    rewrite the configuration file.
    """
    with open(path, "w", encoding="utf-8") as file:
        json.dump(conf, file, indent=4)
