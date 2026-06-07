from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from io import BytesIO
from typing import Any

from scrapli.decorators import timeout_modifier
from scrapli.driver import AsyncDriver
from scrapli.exceptions import ScrapliConnectionNotOpened
from scrapli.response import Response

from . import PROMPTS

logger = logging.getLogger("pywattbox.async_driver")


async def on_open(driver: WattBoxAsyncDriver) -> None:
    logger.debug("On Open")
    # The 800-series presents an in-channel "Username:"/"Password:" telnet login that
    # scrapli's built-in telnet auth does not satisfy (the device rejects it as
    # "Invalid Login"). Over telnet, bypass scrapli auth (see __init__) and log in
    # manually here. Over SSH the transport already authenticates, so keep the
    # original behaviour.
    if driver.transport_name in ("telnet", "asynctelnet"):
        ch = driver.channel

        async def _read_until(token: bytes, timeout: float = 8.0) -> bytes:
            buf = b""
            loop = asyncio.get_event_loop()
            end = loop.time() + timeout
            while token not in buf and loop.time() < end:
                buf += await ch.read()
            return buf

        await _read_until(b"Username:")
        ch.write(driver.auth_username)
        ch.send_return()
        await _read_until(b"Password:")
        ch.write(driver.auth_password)
        ch.send_return()
        await _read_until(b"Logged In")
        # consume the trailing "!\n" so the first command read starts clean
        try:
            await asyncio.wait_for(ch.read(), 0.4)
        except Exception:
            pass
    else:
        await driver.channel._read_until_prompt()


async def on_close(driver: WattBoxAsyncDriver) -> None:
    try:
        driver.channel.write("!Exit")
        driver.channel.send_return()
    except ScrapliConnectionNotOpened:
        pass


class WattBoxAsyncDriver(AsyncDriver):
    def __init__(
        self,
        host: str,
        port: int | None = 22,
        auth_username: str = "",
        auth_password: str = "",
        auth_private_key: str = "",
        auth_private_key_passphrase: str = "",
        auth_strict_key: bool = False,
        auth_bypass: bool = False,
        timeout_socket: float = 5.0,
        timeout_transport: float = 5.0,
        timeout_ops: float = 5.0,
        comms_prompt_pattern: str = PROMPTS,
        comms_return_char: str = "\n",
        ssh_config_file: str | bool = False,
        ssh_known_hosts_file: str | bool = False,
        on_init: Callable[..., Any] | None = None,
        on_open: Callable[..., Any] | None = on_open,
        on_close: Callable[..., Any] | None = on_close,
        transport: str = "asyncssh",
        transport_options: dict[str, Any] | None = None,
        channel_log: str | bool | BytesIO = False,
        channel_log_mode: str = "write",
        channel_lock: bool = True,
        logging_uid: str = "",
    ) -> None:
        # scrapli's telnet auth does not work against the WattBox login prompt;
        # bypass it and authenticate manually in on_open. SSH keeps normal auth.
        if transport in ("telnet", "asynctelnet"):
            auth_bypass = True

        super().__init__(
            host=host,
            port=port,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_private_key=auth_private_key,
            auth_private_key_passphrase=auth_private_key_passphrase,
            auth_strict_key=auth_strict_key,
            auth_bypass=auth_bypass,
            timeout_socket=timeout_socket,
            timeout_transport=timeout_transport,
            timeout_ops=timeout_ops,
            comms_prompt_pattern=comms_prompt_pattern,
            comms_return_char=comms_return_char,
            ssh_config_file=ssh_config_file,
            ssh_known_hosts_file=ssh_known_hosts_file,
            on_init=on_init,
            on_open=on_open,
            on_close=on_close,
            transport=transport,
            transport_options=transport_options,
            channel_log=channel_log,
            channel_log_mode=channel_log_mode,
            channel_lock=channel_lock,
            logging_uid=logging_uid,
        )

    async def _open(self, force: bool = False) -> None:
        if force or not self.transport.isalive():
            await self.open()

    @timeout_modifier
    async def _send_command(self, command: str) -> Response:
        """Send a command and return its single-line response.

        WattBox replies one line per request as ``?Key=value`` (or ``OK`` / ``#Error``
        for ``!`` control messages). The device does not reliably echo the command, and
        values can contain spaces and commas (e.g. ``?OutletName``), so scrapli's prompt
        matching is unreliable here -- read the matching reply line directly instead.
        """
        await self._open()

        response = Response(
            host=self._base_transport_args.host,
            channel_input=command,
            failed_when_contains="#Error",
        )

        logger.debug("Sending Command: %s", command)

        key = command.split("=", 1)[0].encode()
        if command.startswith("?"):
            reply_pattern = re.compile(b"(?m)^" + re.escape(key) + b"=(.*)")
        else:
            reply_pattern = re.compile(b"(OK|#Error)")

        raw_response = b""
        async with self.channel._channel_lock():
            self.channel.write(command)
            self.channel.send_return()
            loop = asyncio.get_event_loop()
            end = loop.time() + 6.0
            while loop.time() < end and not reply_pattern.search(raw_response):
                try:
                    raw_response += await asyncio.wait_for(self.channel.read(), 1.0)
                except Exception:
                    break

        match = reply_pattern.search(raw_response)
        processed_response = match.group(1).rstrip() if match else b""
        logger.debug("processed_response: %s", processed_response)
        response.record_response(processed_response)
        response.raw_result = raw_response
        return response
