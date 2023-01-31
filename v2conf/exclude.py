#! /usr/bin/env python3.9

"""
This module helps you find leased IP addresses of a country and make sure that when
users are trying to connect to a website in that country, they will be connected directly.

GitHub: https://github.com/Mahyar24/V2Conf
Mahyar@Mahyar24.com, Sun Nov 13 2022
"""
import logging
from typing import Union

import requests


def get_ips(country_code: str, logger: logging.Logger) -> list[str]:
    """
    Get leased IP addresses of a country.
    Based on country codes (ISO 3166-1 alpha-2).
    """
    link = (
        f"https://stat.ripe.net/data/country-resource-list/data.json"
        f"?resource={country_code}&v4_format=prefix"
    )
    for _ in range(5):
        try:
            resp = requests.get(link, timeout=20)
            resp.raise_for_status()
        except requests.exceptions.RequestException:
            pass
        else:
            try:
                return resp.json()["data"]["resources"]["ipv4"]
            except KeyError:
                logger.error(f"{link!r} doesn't respond on planned schema")
                return []

    logger.error(f"Failed to connect to {link!r}")
    return []


def make_ip_rule(
    country_code: str, freedom_tag: str, logger: logging.Logger
) -> dict[str, Union[str, list[str]]]:
    """
    Make a rule to exclude IP addresses of a country.
    """
    return {
        "type": "field",
        "ip": get_ips(country_code, logger),
        "outboundTag": freedom_tag,
    }
