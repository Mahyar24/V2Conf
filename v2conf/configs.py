#! /usr/bin/env python3.9

"""
This module is used for reading and writing configuration files.

GitHub: https://github.com/Mahyar24/V2Conf
Mahyar@Mahyar24.com, Sun Nov 13 2022
"""


import argparse
import io
import json
import logging
import random
import secrets
import socket
from contextlib import closing
from pathlib import Path
from typing import Optional, Union

import json5kit

from .exclude import make_ip_rule


def read_json5_file(file: io.TextIOWrapper) -> dict:
    """
    Reading JSON5 files.
    """
    source = file.read()
    json_source = json5kit.parse(source).to_json()
    return json.loads(json_source)


def find_n_unused_port(num: int, banned_ports: Optional[set[int]] = None) -> list[int]:
    """
    Find n unique unused port and return them as a list.
    """
    ports: set[int] = set()
    while len(ports) < num:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.bind(("", 0))
            port = sock.getsockname()[1]
            # Checking if the port is banned
            if banned_ports is not None and port in banned_ports:
                continue
            ports.add(port)

    return list(ports)


def make_http_inbounds(
    outbound_tags: list[str], banned_ports: set[int], logger: logging.Logger
) -> list[dict]:
    """
    For every outbound, create an HTTP inbound for examining the performance.
    Banning used ports in inbounds.
    """
    http_inbounds = []

    ports = find_n_unused_port(len(outbound_tags), banned_ports)

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

    if not inbounds_path.is_dir():
        raise ValueError("Inbounds directory not found!")

    inbounds = {}
    tags = []
    for config in inbounds_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = read_json5_file(file)
        try:
            inbounds[data["tag"]] = data
        except KeyError as err:
            raise KeyError(f"Tag not found in {config.name!r}") from err
        else:
            if data["tag"].startswith("inbound-http-test-"):
                raise ValueError(
                    f"'inbound-http-test-*' is reserved for internal use. "
                    f"Change the tag in {config.name!r}"
                )

            if (tag := data["tag"]) in tags:
                raise ValueError(
                    f"Duplicated tags; {tag!r} already exist! Change the tag in {config.name!r}"
                )
            tags.append(tag)

    if len(inbounds) < 1:
        raise ValueError("No inbound config found!")

    return inbounds


def read_outbounds(path: Path) -> dict[str, dict]:
    """
    Reading outbounds from the path. At least one freedom outbound is required.
    """
    outbounds_path = path / "outbounds"

    if not outbounds_path.is_dir():
        raise ValueError("Outbounds directory not found!")

    outbounds = {}
    tags = []
    check_freedom = False
    for config in outbounds_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = read_json5_file(file)
        try:
            outbounds[data["tag"]] = data
        except KeyError as err:
            raise KeyError(f"Tag not found in {config.name!r}") from err
        else:
            if (tag := data["tag"]) in tags:
                raise ValueError(
                    f"Duplicated tags; {tag!r} already exist! Change the tag in {config.name!r}"
                )
            tags.append(tag)

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

    if not rules_path.is_dir():
        raise ValueError("Rules directory not found!")

    rules = {}
    tags = []
    for config in rules_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = read_json5_file(file)
        try:
            rules[data["tag"]] = data
        except KeyError as err:
            raise KeyError(f"Tag not found in {config.name!r}") from err
        else:
            if (tag := data["tag"]) in tags:
                raise ValueError(
                    f"Duplicated tags; {tag!r} already exist! Change the tag in {config.name!r}"
                )
            tags.append(tag)

    return rules


def read_reverses(path: Path) -> tuple[dict[str, list[dict]], list[str]]:
    """
    Reading reverse configs from the path.
    """
    reverse_path = path / "reverse"

    portals = []
    bridges = []
    portal_tags = []

    reverse_conf: dict[str, list[dict]] = {}

    if not reverse_path.is_dir():
        return reverse_conf, []

    for config in reverse_path.glob("*.json"):
        with open(config, "r", encoding="utf-8") as file:
            data = read_json5_file(file)

        data_portals = data.get("portals", [])
        bridge_portals = data.get("bridges", [])
        if data_portals:
            portals.extend(data_portals)
        if bridge_portals:
            bridges.extend(bridge_portals)

        if not portals and not bridges:
            raise ValueError(f"No portals or bridges found in {config.name!r}")

        for portal in data_portals:
            try:
                tag = portal["tag"]
            except KeyError as err:
                raise KeyError(f"Tag not found in {config.name!r}") from err
            else:
                if tag in portal_tags:
                    raise ValueError(
                        f"Duplicated portal tags; {tag!r} already exist!"
                        f" Change the tag in {config.name!r}"
                    )
                portal_tags.append(tag)

    if portals:
        reverse_conf["portals"] = portals
    if bridges:
        reverse_conf["bridges"] = bridges

    return reverse_conf, portal_tags


def find_freedom_tag(
    args: argparse.Namespace, logger: logging.Logger, outbounds: dict[str, dict]
) -> str:
    """
    Find the tag of the freedom outbound.
    """
    freedom_outbounds = {
        k: v for k, v in outbounds.items() if v["protocol"] == "freedom"
    }

    if args.freedom_tag:
        # Check if the freedom tag is valid.
        if args.freedom_tag in freedom_outbounds.keys():
            return args.freedom_tag
        raise ValueError(
            f"{args.freedom_tag!r} is not found in freedom protocols outbounds!"
        )

    # Guessing the correct freedom tag.
    # We suppose the right one is the one without `settings` field -
    # or with minimum keys in the `settings` field.
    freedom_tag = min(
        freedom_outbounds,
        key=lambda k: (
            -1
            if "settings" not in freedom_outbounds[k]
            else len(freedom_outbounds[k]["settings"])
        ),
    )
    logger.warning(
        f"No freedom tag specified, guessing the correct one to be {freedom_tag!r}"
    )
    return freedom_tag


def make_rules(
    path: Path,
    logger: logging.Logger,
    *,
    geoip: bool,
    county_code: str,
    http_inbounds: list[dict],
    inbound_tags: list[str],
    freedom_outbound_tag: str,
    outbound: str,
) -> list[dict]:
    """
    Make rules for the configuration file.
    """

    # Rules for excluding domestic IPs.
    if geoip:
        ip_rule: dict[str, Union[str, list[str]]] = {
            "type": "field",
            "outboundTag": freedom_outbound_tag,
            "ip": [f"geoip:{county_code.lower()}"],
        }
        logger.info(f"'geoip:{county_code.lower()}' going to {freedom_outbound_tag!r}")
    else:
        ip_rule = make_ip_rule(county_code, freedom_outbound_tag, logger)
        logger.info(f"Excluding {len(ip_rule['ip'])} IPs for {county_code!r}")

    # Rules from rules directory
    rules = list(read_rules(path).values())
    logger.info(f"Read {len(rules)} rules")

    # Finding already designated inbounds.
    designated_inbounds: set[str] = set()
    for rule in rules:
        if "inboundTag" in rule and "outboundTag" in rule and rule["type"] == "field":
            designated_inbounds.update(rule["inboundTag"])
    if designated_inbounds:
        logger.warning(f"Already designated inbounds: {list(designated_inbounds)}")

    # If downloading IPs from the internet failed, we must not
    # create a rule with empty list; otherwise v2ray will crash.
    if ip_rule["ip"]:
        rules += [ip_rule]

    # Rules for routing http proxies to their corresponding outbounds.
    for http_inbound in http_inbounds:
        rules.append(
            {
                "inboundTag": [http_inbound["tag"]],
                "outboundTag": http_inbound["tag"].removeprefix("inbound-http-test-"),
                "type": "field",
            }
        )

    logger.info(f"Using {outbound!r} as main outbound")
    rules.append(
        {
            "inboundTag": list(set(inbound_tags) - designated_inbounds),
            "outboundTag": outbound,
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
    inbounds_used_ports = {
        inbound["port"]
        for inbound in inbounds.values()
        if inbound.get("port") is not None
    }

    if args.stats_port in inbounds_used_ports:
        raise ValueError(
            f"Stats port {args.stats_port!r} already used by another inbound!"
        )

    outbounds = read_outbounds(args.path_conf_dir)
    reverses_conf, portal_tags = read_reverses(args.path_conf_dir)

    if reverses_conf:
        # Adding logger info for reverses, but maybe portals or bridges keys are non-existent.
        num_portals = 0
        num_bridges = 0

        if "portals" in reverses_conf:
            num_portals = len(reverses_conf["portals"])
        if "bridges" in reverses_conf:
            num_bridges = len(reverses_conf["bridges"])
        logger.info(
            f"Read reverses, {num_bridges} bridges and {num_portals} portals found"
        )

    # We should only make http inbounds for the outbounds that are not freedom or blackhole.
    vpn_outbounds = [
        k for k, v in outbounds.items() if v["protocol"] not in ("freedom", "blackhole")
    ]
    # Check to see if any tags are in both `vpn_outbounds` and `portal_tags`.
    if portal_tags:
        duplicates = list(set(portal_tags) & set(vpn_outbounds))
        if duplicates:
            raise ValueError(f"Duplicated outbound tags found: {duplicates!r}")
        vpn_outbounds.extend(portal_tags)

    if outbound_tag not in vpn_outbounds:
        raise ValueError(
            f"{outbound_tag!r} is not found in vpn outbounds! "
            "Please specify a valid outbound tag."
        )
    if args.backup_outbounds:
        for backup in args.backup_outbounds:
            if backup not in vpn_outbounds:
                raise ValueError(
                    f"{backup!r} is not found in vpn outbounds! "
                    "Please specify a valid backup outbound tag."
                )

    if len(vpn_outbounds) < 2:
        raise ValueError(
            "At least two non-freedom/non-blackhole outbounds are required!"
        )
    if len(vpn_outbounds) - len(args.backup_outbounds) < 1:
        raise ValueError(
            "At least one non-freedom/non-blackhole outbound"
            " is required to also not be in backup outbounds!"
        )

    logger.info(
        f"Read {len(outbounds)} outbounds, {len(vpn_outbounds)} vpn outbounds,"
        f" {len(args.backup_outbounds)} backup outbounds"
    )

    freedom = find_freedom_tag(args, logger, outbounds)

    http_inbounds = make_http_inbounds(
        vpn_outbounds,
        # Make sure the inbound ports or stats port is not used by any inbound.
        inbounds_used_ports | {args.stats_port},
        logger,
    )

    # If nothing is specified for `outbound_tag`, route all traffic to
    # a random vpn outbound. (Cold start), Otherwise, route all traffic
    # to the specified (best) outbound.
    if outbound_tag is None:
        logger.info("Cold start, routing all traffic to a random vpn outbound")
        outbound_tag = random.choice(vpn_outbounds)

    rules = make_rules(
        args.path_conf_dir,
        logger,
        geoip=not args.no_geoip,
        county_code=args.country_code,
        http_inbounds=http_inbounds,
        inbound_tags=list(inbounds.keys()),
        freedom_outbound_tag=freedom,
        outbound=outbound_tag,
    )

    conf = {
        "log": {"loglevel": args.log_level},
        "inbounds": list(inbounds.values()) + http_inbounds,
        "outbounds": list(outbounds.values()),
        "routing": {"domainStrategy": "UseIPv4", "rules": rules},
    }
    if reverses_conf:
        conf = conf | {"reverse": reverses_conf}

    if args.stats:
        conf["stats"] = {}
        stats_users_cond = args.users_only or (not args.sys_only)
        stats_sys_cond = args.sys_only or (not args.users_only)
        conf["policy"] = {
            "levels": {
                "0": {
                    "statsUserUplink": stats_users_cond,
                    "statsUserDownlink": stats_users_cond,
                }
            },
            "system": {
                "statsInboundUplink": stats_sys_cond,
                "statsInboundDownlink": stats_sys_cond,
                "statsOutboundUplink": stats_sys_cond,
                "statsOutboundDownlink": stats_sys_cond,
            },
        }
        conf["api"] = {
            "services": ["HandlerService", "LoggerService", "StatsService"],
            "tag": "api",
        }
        conf["inbounds"].append(
            {
                "listen": "127.0.0.1",
                "port": args.stats_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api",
                "sniffing": None,
            },
        )
        conf["routing"]["rules"].append(
            {"inboundTag": ["api"], "outboundTag": "api", "type": "field"}
        )

    return conf


def write_conf(path: Path, conf: dict) -> None:
    """
    Rewrite the configuration file.
    """
    with open(path, "w", encoding="utf-8") as file:
        json.dump(conf, file, indent=4)
