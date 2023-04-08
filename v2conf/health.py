#! /usr/bin/env python3.9

"""
In this module, we are going to check the health and performance of
all the outbounds and rank them based on their health and performance.

GitHub: https://github.com/Mahyar24/V2Conf
Mahyar@Mahyar24.com, Sun Nov 13 2022
"""

import argparse
import asyncio
import logging
import math
import statistics
import time
from collections import ChainMap
from typing import Union

import aiohttp


def calculate_ema(nums: list[Union[int, float]], n_th: int, smoothing: float) -> float:
    """
    Calculating Exponential Moving Average.
    """
    # Removing NaNs.
    selected_nums = list(filter(lambda x: not math.isnan(x), nums))[-n_th:]
    # If no number exist (happens in early stages and only in latency)
    # return 0. It's harmless cause when latency is NaN, we rank the outbound lower by using
    # No. of failures.
    if not selected_nums:
        return 0.0

    ema = statistics.mean(selected_nums)
    for num in selected_nums:
        ema = (num * (smoothing / (1 + n_th))) + ema * (1 - (smoothing / (1 + n_th)))
    return ema


async def check_health(
    session: aiohttp.ClientSession,
    outbound_name: str,
    username: str,
    password: str,
    proxy: str,
    test_site: str,
    *,
    num_of_tries: int,
    timeout: int,
) -> dict[str, list[float]]:
    """
    Check the health of a proxy by pinging it and checking its latency.
    If an error or timeout happens, it will be recorded as a NaN,
    otherwise we will record the latency.
    """
    result: list[float] = []

    proxy_auth = aiohttp.BasicAuth(username, password)
    for _ in range(num_of_tries):
        start_time = time.perf_counter()
        try:
            async with session.get(
                test_site, proxy=proxy, proxy_auth=proxy_auth, timeout=timeout
            ) as resp:
                if resp.ok:
                    # Fetch the data chunk by chuck
                    async for _ in resp.content.iter_chunked(2048):
                        pass
                    result.append(time.perf_counter() - start_time)
                else:
                    result.append(float("nan"))
        except (
            asyncio.exceptions.TimeoutError,
            aiohttp.client_exceptions.ClientError,
        ):
            result.append(float("nan"))

    return {outbound_name: result}


def calculate(results: list[float]) -> tuple[int, float]:
    """
    Calculate the health of an outbound.
    Returns a tuple of (number of errors, average latency).
    """
    number_of_nans = sum(map(math.isnan, results))
    if number_of_nans == len(results):
        return number_of_nans, float("nan")
    return number_of_nans, statistics.mean(filter(lambda x: not math.isnan(x), results))


def process_results(
    results: dict[str, tuple[int, float]],
    historical_results: list[dict[str, tuple[int, float]]],
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[str]:
    """
    Processing fixed-schema results based on `--ema` and `--timeout-penalty` flags.
    """
    nan_to_zero = lambda x: 0.0 if math.isnan(x) else x

    outbound_keys = historical_results[0].keys()

    if args.timeout_penalty:
        processed_results = {
            k: calculate_ema(
                [
                    (
                        (
                            (row[k][0] * args.timeout_penalty)
                            + (
                                nan_to_zero(row[k][1])
                                * (args.num_of_tries - (row[k][0]))
                            )
                        )
                        / args.num_of_tries
                    )
                    for row in historical_results
                ],
                # N = 1, does nothing.
                n_th=1 if not args.ema else int(args.ema[0]),
                smoothing=1 if not args.ema else args.ema[1],
            )
            for k in outbound_keys
        }
    else:
        if args.ema:
            processed_results = {
                k: (
                    calculate_ema(
                        [row[k][0] for row in historical_results],
                        n_th=int(args.ema[0]),
                        smoothing=args.ema[1],
                    ),
                    calculate_ema(
                        [row[k][1] for row in historical_results],
                        n_th=int(args.ema[0]),
                        smoothing=args.ema[1],
                    ),
                )
                for k in outbound_keys
            }
        else:
            processed_results = results

    if args.ema:
        logger.info(
            f"Using EMA ({int(args.ema[0])}, {args.ema[1]:.2f}) for ranking outbounds."
            f" Results: {processed_results}"
        )
    return list(
        dict(sorted(processed_results.items(), key=lambda item: item[1])).keys()
    )


async def rank_outbounds(
    historical_results: list[dict[str, tuple[int, float]]],
    args: argparse.Namespace,
    logger: logging.Logger,
    *,
    http_inbounds: list[dict],
) -> tuple[list[str], list[dict[str, tuple[int, float]]]]:
    """
    Rank the outbounds by their health. best to worst.
    If `--timeout-penalty` is disabled, we will sort the outbounds first by number of errors,
    then by average latency of succeeded attempts; otherwise, sorting will be based on overall
    calculated average latency and failures will be considered as attempts
    with `--timeout-penalty` latency.
    """
    coroutines = []

    async with aiohttp.ClientSession() as session:
        for http_inbound in http_inbounds:
            coroutines.append(
                asyncio.create_task(
                    check_health(
                        session,
                        http_inbound["tag"].split("-")[-1],
                        http_inbound["accounts"][0]["user"],
                        http_inbound["accounts"][0]["pass"],
                        f"http://{http_inbound['listen']}:{http_inbound['port']}",
                        args.website,
                        num_of_tries=args.num_of_tries,
                        timeout=args.timeout,
                    )
                )
            )
        results = dict(ChainMap(*await asyncio.gather(*coroutines)))

    results = {k: calculate(v) for k, v in results.items()}
    logger.info(f"Results: {results}")

    historical_results.append(results)
    num_historical_results = 1 if not args.ema else int(args.ema[0])
    historical_results = historical_results[-num_historical_results:]

    return (
        process_results(results, historical_results, args, logger),
        historical_results,
    )
