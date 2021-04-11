"""Support for Broadlink devices."""
import logging
import socket
import threading
import random
import time
import typing as t

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import exceptions as e
from .protocol import Datetime

_LOGGER = logging.getLogger(__name__)

HelloResponse = t.Tuple[int, t.Tuple[str, int], str, str, bool]


def scan(
    timeout: int = 10,
    local_ip_address: str = None,
    discover_ip_address: str = "255.255.255.255",
    discover_ip_port: int = 80,
) -> t.Generator[HelloResponse, None, None]:
    """Broadcast a hello message and yield responses."""
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    if local_ip_address:
        conn.bind((local_ip_address, 0))
        port = conn.getsockname()[1]
    else:
        local_ip_address = "0.0.0.0"
        port = 0

    packet = bytearray(0x30)
    packet[0x08:0x14] = Datetime.pack(Datetime.now())
    packet[0x18:0x1C] = socket.inet_aton(local_ip_address)[::-1]
    packet[0x1C:0x1E] = port.to_bytes(2, "little")
    packet[0x26] = 6

    checksum = sum(packet, 0xBEAF) & 0xFFFF
    packet[0x20:0x22] = checksum.to_bytes(2, "little")

    start_time = time.time()
    discovered = []

    try:
        while (time.time() - start_time) < timeout:
            time_left = timeout - (time.time() - start_time)
            conn.settimeout(min(1, time_left))
            conn.sendto(packet, (discover_ip_address, discover_ip_port))

            while True:
                try:
                    resp, host = conn.recvfrom(1024)
                except socket.timeout:
                    break

                devtype = resp[0x34] | resp[0x35] << 8
                mac = resp[0x3A:0x40][::-1]

                if (host, mac, devtype) in discovered:
                    continue
                discovered.append((host, mac, devtype))

                name = resp[0x40:].split(b"\x00")[0].decode()
                is_locked = bool(resp[0x7F])
                yield devtype, host, mac, name, is_locked
    finally:
        conn.close()


def ping(address: str, port: int = 80) -> None:
    """Send a ping packet to an address.

    This packet feeds the watchdog timer of firmwares >= v53.
    Useful to prevent reboots when the cloud cannot be reached.
    It must be sent every 2 minutes in such cases.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        packet = bytearray(0x30)
        packet[0x26] = 1
        conn.sendto(packet, (address, port))


class Device:
    """Controls a Broadlink device."""

    TYPE = "Unknown"

    __INIT_KEY = "097628343fe99e23765c1513accf8b02"
    __INIT_VECT = "562e17996d093d28ddb3ba695a2e6f58"

    def __init__(
        self,
        host: t.Tuple[str, int],
        mac: t.Union[bytes, str],
        devtype: int,
        timeout: int = 10,
        name: str = "",
        model: str = "",
        manufacturer: str = "",
        is_locked: bool = False,
    ) -> None:
        """Initialize the controller."""
        self.host = host
        self.mac = bytes.fromhex(mac) if isinstance(mac, str) else mac
        self.devtype = devtype
        self.timeout = timeout
        self.name = name
        self.model = model
        self.manufacturer = manufacturer
        self.is_locked = is_locked
        self.pkt_no = random.randint(0x8000, 0xFFFF)
        self.conn_id = 0
        self.type = self.TYPE  # For backwards compatibility.
        self.lock = threading.Lock()

        self.aes = None
        self.update_aes(bytes.fromhex(self.__INIT_KEY))

    def __repr__(self) -> str:
        """Return a formal representation of the device."""
        return (
            "%s.%s(%s, mac=%r, devtype=%r, timeout=%r, name=%r, "
            "model=%r, manufacturer=%r, is_locked=%r)"
        ) % (
            self.__class__.__module__,
            self.__class__.__qualname__,
            self.host,
            self.mac,
            self.devtype,
            self.timeout,
            self.name,
            self.model,
            self.manufacturer,
            self.is_locked,
        )

    def __str__(self) -> str:
        """Return a readable representation of the device."""
        return "%s (%s / %s:%s / %s)" % (
            self.name or "Unknown",
            " ".join(filter(None, [self.manufacturer, self.model, hex(self.devtype)])),
            *self.host,
            ":".join(format(x, "02X") for x in self.mac),
        )

    def update_aes(self, key: bytes) -> None:
        """Update AES."""
        self.aes = Cipher(
            algorithms.AES(bytes(key)),
            modes.CBC(bytes.fromhex(self.__INIT_VECT)),
            backend=default_backend(),
        )

    def encrypt(self, payload: bytes) -> bytes:
        """Encrypt the payload."""
        # The blocksize must be a multiple of 16.
        padding = (16 - len(payload)) % 16
        payload = bytes(payload + padding * b'\0')

        encryptor = self.aes.encryptor()
        return encryptor.update(payload) + encryptor.finalize()

    def decrypt(self, payload: bytes) -> bytes:
        """Decrypt the payload."""
        decryptor = self.aes.decryptor()
        return decryptor.update(bytes(payload)) + decryptor.finalize()

    def auth(self) -> bool:
        """Authenticate to the device."""
        self.conn_id = 0
        self.update_aes(bytes.fromhex(self.__INIT_KEY))

        packet = bytearray(0x50)
        packet[0x04:0x14] = [0x31] * 16
        packet[0x1E] = 0x01
        packet[0x2D] = 0x01
        packet[0x30:0x36] = "Test 1".encode()

        resp, err = self.send_packet(0x65, packet)
        e.check_error(err)

        self.conn_id = int.from_bytes(resp[:0x4], "little")
        self.update_aes(resp[0x04:0x14])
        return True

    def hello(self, local_ip_address=None) -> bool:
        """Send a hello message to the device.

        Device information is checked before updating name and lock status.
        """
        responses = scan(
            timeout=self.timeout,
            local_ip_address=local_ip_address,
            discover_ip_address=self.host[0],
            discover_ip_port=self.host[1],
        )
        try:
            devtype, _, mac, name, is_locked = next(responses)

        except StopIteration as err:
            raise e.NetworkTimeoutError(
                -4000,
                "Network timeout",
                f"No response received within {self.timeout}s",
            ) from err

        if mac != self.mac:
            raise e.DataValidationError(
                -2040,
                "Device information is not intact",
                "The MAC address is different",
                f"Expected {self.mac} and received {mac}",
            )

        if devtype != self.devtype:
            raise e.DataValidationError(
                -2040,
                "Device information is not intact",
                "The product ID is different",
                f"Expected {self.devtype} and received {devtype}",
            )

        self.name = name
        self.is_locked = is_locked
        return True

    def ping(self) -> None:
        """Ping the device.

        This packet feeds the watchdog timer of firmwares >= v53.
        Useful to prevent reboots when the cloud cannot be reached.
        It must be sent every 2 minutes in such cases.
        """
        ping(self.host[0], port=self.host[1])

    def get_fwversion(self) -> int:
        """Get firmware version."""
        packet = bytearray([0x68])
        resp, err = self.send_packet(0x6A, packet)
        e.check_error(err)
        return resp[0x4] | resp[0x5] << 8

    def set_name(self, name: str) -> None:
        """Set device name."""
        packet = bytearray(4)
        packet += name.encode("utf-8")
        packet += bytearray(0x50 - len(packet))
        packet[0x43] = self.is_locked
        err = self.send_packet(0x6A, packet)[1]
        e.check_error(err)
        self.name = name

    def set_lock(self, state: bool) -> None:
        """Lock/unlock the device."""
        packet = bytearray(4)
        packet += self.name.encode("utf-8")
        packet += bytearray(0x50 - len(packet))
        packet[0x43] = bool(state)
        err = self.send_packet(0x6A, packet)[1]
        e.check_error(err)
        self.is_locked = bool(state)

    def get_type(self) -> str:
        """Return device type."""
        return self.type

    def send_packet(
        self,
        pkt_type: int,
        payload: bytes = b"",
        protected=True,
        should_wait=True,
        retry_intvl: float = 1.0,
    ) -> t.Union[t.Tuple[bytes, int], None]:
        """Send packet to the device."""
        if protected:
            exp_resp = pkt_type + 900 & 0xFFFF
            with self.lock:
                pkt_no = self.pkt_no = ((self.pkt_no + 1) | 0x8000) & 0xFFFF

            packet = bytearray(0x38)
            packet[0x00:0x08] = [0x5A, 0xA5, 0xAA, 0x55, 0x5A, 0xA5, 0xAA, 0x55]
            packet[0x24:0x26] = self.devtype.to_bytes(2, "little")
            packet[0x26:0x28] = pkt_type.to_bytes(2, "little")
            packet[0x28:0x2A] = pkt_no.to_bytes(2, "little")
            packet[0x2A:0x30] = self.mac[::-1]
            packet[0x30:0x34] = self.conn_id.to_bytes(4, "little")

            payload_checksum = sum(payload, 0xBEAF) & 0xFFFF
            packet[0x34:0x36] = payload_checksum.to_bytes(2, "little")
            packet.extend(self.encrypt(payload))

        else:
            exp_resp = pkt_type + 1
            pkt_no = 0

            packet = bytearray(0x30)
            packet[0x26:0x28] = pkt_type.to_bytes(2, "little")

        checksum = sum(packet, 0xBEAF) & 0xFFFF
        packet[0x20:0x22] = checksum.to_bytes(2, "little")
        packet = bytes(packet)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            timeout = self.timeout
            start_time = time.time()
            should_delay = False
            errors = []

            while True:
                if should_delay:
                    time.sleep(retry_intvl)

                time_left = timeout - (time.time() - start_time)
                if time_left < 0:
                    if not errors:
                        raise e.NetworkTimeoutError(
                            -4000,
                            "Network timeout",
                            f"No response received within {timeout}s",
                        )
                    if len(errors) == 1:
                        raise errors[0]
                    raise e.MultipleErrors(errors)

                conn.sendto(packet, self.host)
                _LOGGER.debug("%s sent to %s", packet, self.host)

                if not should_wait:
                    return None

                conn.settimeout(min(retry_intvl, time_left))
                try:
                    return self._recv(conn, exp_resp, pkt_no)

                except socket.timeout:
                    should_delay = False
                    continue

                except e.AuthorizationError:
                    raise

                except e.BroadlinkException as err:

                    _LOGGER.debug(err)
                    errors.append(err)
                    should_delay = True
                    continue

    def _recv(
        self,
        conn: socket.socket,
        exp_resp: int,
        exp_pkt_no: int,
    ) -> t.Tuple[bytes, int]:
        """Receive packet from the device."""
        data, addr = conn.recvfrom(2048)
        _LOGGER.debug("%s received from %s", data, addr)

        if len(data) < 0x30:
            raise e.DataValidationError(
                -4007,
                "Received data packet length error",
                f"Expected at least 48 bytes and received {len(data)}",
            )

        nom_checksum = int.from_bytes(data[0x20:0x22], "little")
        real_checksum = sum(data, 0xBEAF) - sum(data[0x20:0x22]) & 0xFFFF

        if nom_checksum != real_checksum:
            raise e.DataValidationError(
                -4008,
                "Received data packet check error",
                f"Expected a checksum of {nom_checksum} and received {real_checksum}",
            )

        err_code = int.from_bytes(data[0x22:0x24], "little", signed=True)
        resp_type = int.from_bytes(data[0x26:0x28], "little")

        if resp_type != exp_resp:
            raise e.DataValidationError(
                -4009,
                "Received data packet information type error",
                f"Expected {exp_resp} and received {resp_type}",
            )

        if not any(data[:0x08]) or not any(data[0x30:]):
            return data[0x30:], err_code

        pkt_no = int.from_bytes(data[0x28:0x2A], "little")
        if pkt_no != exp_pkt_no:
            raise e.DataValidationError(
                f"Invalid packet number: Expected {exp_pkt_no} and received {pkt_no}"
            )

        mac_addr = data[0x2A:0x30][::-1]
        if mac_addr != self.mac:
            raise e.DataValidationError(
                f"Invalid MAC address: Expected {self.mac} and received {mac_addr}"
            )

        conn_id = int.from_bytes(data[0x30:0x34], "little")
        nom_checksum = int.from_bytes(data[0x34:0x36], "little")
        payload = data[0x38:]

        if len(payload) % 16:
            raise e.DataValidationError(
                -4010,
                "Received encrypted data packet length error",
                f"Expected a multiple of 16 and received {len(payload)}",
            )

        if self.conn_id and self.conn_id != conn_id:
            raise e.AuthorizationError(
                -4012,
                "Device control ID error",
                f"Expected {self.conn_id} and received {conn_id}",
            )

        payload = self.decrypt(payload)
        real_checksum = sum(payload, 0xBEAF) & 0xFFFF

        if payload and nom_checksum != real_checksum:
            raise e.DataValidationError(
                -4011,
                "Received encrypted data packet check error",
                f"Expected a checksum of {nom_checksum} and received {real_checksum}",
            )

        return payload, err_code
