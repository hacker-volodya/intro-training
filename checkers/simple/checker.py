#!/usr/bin/env python3
import inspect
from enum import Enum
from sys import argv
import sys
import traceback
import requests
import re


DEBUG = True


"""
    Methods
"""


def info():
    print('vulns: 1:1:1\npublic_flag_description: secret\n', flush=True, end="")
    exit(101)


def check(host: str):
    secret_id = store(host, "check")
    if load(host, secret_id) != "check":
        raise MumbleError("Check failed")


def put(host: str, flag_id: str, flag: str, vuln: str):
    secret_id = store(host, flag)
    print(secret_id, end="")


def get(host: str, flag_id: str, flag: str, vuln: str):
    stored_flag = load(host, flag_id)
    if stored_flag != flag:
        raise CorruptError("Wrong flag")


"""
    Helpers
"""


def store(host, secret):
    _log(f"store {secret}")
    response = requests.post(f"http://{host}:3337/", data={"secret": secret})
    _log(f"got {response.text}")
    if response.status_code != 200:
        raise MumbleError(f"Store failed, response {response.status_code}")
    result = re.findall("Your secret id: ([^;]+);", response.text)
    if not result:
        raise MumbleError("Store failed, no secret id")
    return result[0]


def load(host, secret_id):
    _log(f"load {secret_id}")
    response = requests.get(f"http://{host}:3337/{secret_id}")
    _log(f"got {response.text}")
    if response.status_code == 404:
        raise CorruptError("No such flag")
    if response.status_code != 200:
        raise MumbleError(f"Load failed, response {response.status_code}")
    result = re.findall("Your secret is (.+)", response.text)
    if not result:
        raise MumbleError("Load failed, no secret")
    return result[0]


def _log(obj):
    if DEBUG and obj:
        caller = inspect.stack()[1].function
        print(f"[{caller}] {obj}", file=sys.stderr)
    return obj


class ExitStatus(Enum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110


class CheckerError(RuntimeError):
    def __init__(self, *args: object):
        super().__init__(*args)


class CorruptError(CheckerError):
    def __init__(self, *args: object):
        super().__init__(*args)


class MumbleError(CheckerError):
    def __init__(self, *args: object):
        super().__init__(*args)


class DownError(CheckerError):
    def __init__(self, *args: object):
        super().__init__(*args)


class WrongArgumentsError(CheckerError):
    def __init__(self, *args: object):
        super().__init__(*args)


def die(code: ExitStatus, msg: str):
    if msg:
        print(msg, file=sys.stderr)
    exit(code.value)


def _main():
    try:
        if len(argv) < 3:
            raise WrongArgumentsError()
        cmd = argv[1]
        hostname = argv[2]
        if cmd == "get":
            if len(argv) < 6:
                raise WrongArgumentsError()
            fid, flag, vuln = argv[3], argv[4], argv[5]
            get(hostname, fid, flag, vuln)
        elif cmd == "put":
            if len(argv) < 6:
                raise WrongArgumentsError()
            fid, flag, vuln = argv[3], argv[4], argv[5]
            put(hostname, fid, flag, vuln)
        elif cmd == "check":
            try:
                check(hostname)
            except CorruptError as e:
                raise MumbleError("Corrupt at check") from e
        elif cmd == "info":
            info()
        else:
            raise WrongArgumentsError()
        die(ExitStatus.OK, "OK")
    except CorruptError as e:
        die(ExitStatus.CORRUPT, traceback.format_exc())
    except MumbleError as e:
        die(ExitStatus.MUMBLE, traceback.format_exc())
    except (DownError, IOError) as e:
        die(ExitStatus.DOWN, traceback.format_exc())
    except WrongArgumentsError as e:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Usage: {argv[0]} check|put|get IP FLAGID FLAG",
        )
    except Exception as e:
        die(ExitStatus.CHECKER_ERROR, traceback.format_exc())


if __name__ == "__main__":
    _main()
