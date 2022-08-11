import asyncio
import base64
import binascii
import json
import logging
import struct
import time
import weakref
from abc import ABC, abstractmethod
from collections import namedtuple
from hashlib import md5

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

# version_tuple = (9, 0, 0)
# version = version_string = __version__ = "%d.%d.%d" % version_tuple

_LOGGER = logging.getLogger(__name__)

TuyaPacket = namedtuple("TuyaPacket", "seqno cmd retcode data")

PROTOCOL_VERSION_BYTES_31 = b"3.1"
PROTOCOL_VERSION_BYTES_33 = b"3.3"
PROTOCOL_VERSION_BYTES_34 = b"3.4"

PROTOCOL_33_HEADER = PROTOCOL_VERSION_BYTES_33 + 12 * b"\x00"

SET = "set"
STATUS = "status"
HEARTBEAT = "heartbeat"
UPDATEDPS = "updatedps"  # Request refresh of DPS

TUYA_HEADER_FMT = ">4I"
TUYA_HEADER_RCV_FMT = ">5I"
TUYA_HEADER_SIZE = struct.calcsize(TUYA_HEADER_FMT)
TUYA_HEADER_RCV_SIZE = struct.calcsize(TUYA_HEADER_RCV_FMT)

TUYA_HEADER_END_31_FMT = ">2I"
TUYA_HEADER_END_34_FMT = ">6I"
TUYA_HEADER_END_31_SIZE = struct.calcsize(TUYA_HEADER_END_31_FMT)
TUYA_HEADER_END_34_SIZE = struct.calcsize(TUYA_HEADER_END_34_FMT)

# TUYA_PREFIX = b'\x00\x00U\xaa'
# TUYA_SUFFIX = b'\x00\x00\xaaU'
TUYA_PREFIX = 0x000055AA
TUYA_SUFFIX = 0x0000AA55

HEARTBEAT_INTERVAL = 10

# DPS that are known to be safe to use with update_dps (0x12) command
UPDATE_DPS_WHITELIST = [18, 19, 20]  # Socket (Wi-Fi)


class TuyaLoggingAdapter(logging.LoggerAdapter):
    """Adapter that adds device id to all log points."""

    def process(self, msg, kwargs):
        """Process log point and return output."""
        dev_id = self.extra["device_id"]
        return f"[{dev_id[0:3]}...{dev_id[-3:]}] {msg}", kwargs


class ContextualLogger:
    """Contextual logger adding device id to log points."""

    def __init__(self):
        """Initialize a new ContextualLogger."""
        self._logger = None

    def set_logger(self, logger, device_id):
        """Set base logger to use."""
        self._logger = TuyaLoggingAdapter(logger, {"device_id": device_id})

    def debug(self, msg, *args):
        """Debug level log."""
        return self._logger.log(logging.DEBUG, msg, *args)

    def info(self, msg, *args):
        """Info level log."""
        return self._logger.log(logging.INFO, msg, *args)

    def warning(self, msg, *args):
        """Warning method log."""
        return self._logger.log(logging.WARNING, msg, *args)

    def error(self, msg, *args):
        """Error level log."""
        return self._logger.log(logging.ERROR, msg, *args)

    def exception(self, msg, *args):
        """Exception level log."""
        return self._logger.exception(msg, *args)


class AESCipher:
    """Cipher module for Tuya communication."""

    def __init__(self, key):
        """Initialize a new AESCipher."""
        self.block_size = 16
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    def encrypt(self, raw, use_base64=True):
        """Encrypt data to be sent to device."""
        encryptor = self.cipher.encryptor()
        crypted_text = encryptor.update(self._pad(raw)) + encryptor.finalize()
        return base64.b64encode(crypted_text) if use_base64 else crypted_text

    def decrypt(self, enc, use_base64=True):
        """Decrypt data from device."""
        if use_base64:
            enc = base64.b64decode(enc)

        decryptor = self.cipher.decryptor()
        return self._unpad(decryptor.update(enc) + decryptor.finalize()).decode()

    def _pad(self, data):
        padnum = self.block_size - len(data) & 0xf
        return data + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(data):
        return data[: -ord(data[len(data) - 1 :])]


class HMAC_SHA256:
    """ """

    def __init__(self, key):
        self.key = key

    def set_session_key(self, session_key):
        self.key = session_key

    def hash(self, data):
        self.hasher = hmac.HMAC(self.key, hashes.SHA256())
        self.hasher.update(data)
        return self.hasher.finalize()


class TuyaPacketer:
    """ """

    def __init__(self, device_key, protocol_version):
        self.device_key = device_key
        self.cipher_ecb_aes128 = AESCipher(device_key)
        self.hmac_sha256 = HMAC_SHA256(device_key)

        if protocol_version not in [3.1, 3.3, 3.4]:
            raise Exception(f"Invalid protocol_version '{protocol_version}' of protocol used.")

        self.protocol_version = protocol_version

    def set_local_key(self, local_key):
        """Sets the local_key used in calculation of the session_key"""
        self.local_key = local_key

    def set_remote_key(self, remote_key):
        """Uses remote_key to calculate the session_key"""
        self.remote_key = remote_key

        try:
            self.local_key
        except AttributeError:
            raise Exception("Local_key was not set. Set it before remote_key, so that it can be used in session_key calculation")

        # Calculate session_key
        self.session_key = bytearray()
        for i in range(0x00, 0x10):
            self.session_key.append(self.local_key[i] ^ remote_key[i])
        self.session_key = self.cipher_ecb_aes128.encrypt(self.session_key, use_base64=False)

        # From now on the session is used for calculating the Tuya packet hash
        self.hmac_sha256.set_session_key(self.session_key)

    def pack_message(self, packet):
        """Pack a TuyaMessage into bytes."""

        if self.protocol_version in [3.1, 3.3]:

            if self.protocol_version == 3.3:
                packet.data = self.cipher_ecb_aes128.encrypt(packet.data, False)
                if packet.command_hb not in [0x0A, 0x12]:
                    # add the 3.3 header
                    packet.data = PROTOCOL_33_HEADER + packet.data

            # If prot_version == 3.1 and cmd == SET:
            elif packet.cmd == 0x07: # SET command
                packet.data = self.cipher_ecb_aes128.encrypt(packet.data)
                to_hash = (b"data=" + packet.data + b"||lpv=" + PROTOCOL_VERSION_BYTES_31 + b"||" + self.device_key)
                hasher = md5()
                hasher.update(to_hash)
                hexdigest = hasher.hexdigest()
                packet.data = (PROTOCOL_VERSION_BYTES_31 + hexdigest[8:][:16].encode("latin1") + packet.data)

            # Create full message excluding CRC and suffix
            buffer = struct.pack(TUYA_HEADER_FMT, TUYA_PREFIX, packet.seqno, packet.cmd, len(packet.data) + TUYA_HEADER_END_31_SIZE) + packet.data

            # Calculate CRC, add it together with suffix
            buffer += struct.pack(TUYA_HEADER_END_31_FMT, binascii.crc32(buffer), TUYA_SUFFIX)    

        elif self.protocol_version == 3.4:
            packet.data = self.cipher_ecb_aes128.encrypt(packet.data)

            # Create full message excluding hash and suffix
            buffer = struct.pack(TUYA_HEADER_FMT, TUYA_PREFIX, packet.seqno, packet.cmd, len(packet.data) + TUYA_HEADER_END_34_SIZE) + packet.data

            # Calculate hash, add it together with suffix
            buffer += struct.pack(TUYA_HEADER_END_34_FMT, self.hmac_sha256.hash(buffer), TUYA_SUFFIX)

        return buffer

    def unpack_message(self, data_in):
        """Unpack bytes into a Tuya packet."""

        # Start with Tuya Header
        # Extract prefix, remote_seq_n, command, len, ret_code from recieved data
        _, seqno, cmd, length, retcode = struct.unpack(TUYA_HEADER_RCV_FMT, data_in[:TUYA_HEADER_RCV_SIZE])

        # Check CRC/HASH
        if self.protocol_version in [3.1, 3.3]:
            data = data_in[TUYA_HEADER_SIZE: -TUYA_HEADER_END_31_SIZE]
            crc_exp, _ = struct.unpack(TUYA_HEADER_END_31_FMT, data_in[-TUYA_HEADER_END_31_SIZE:])
            crc_calc = binascii.crc32(data_in[: -TUYA_HEADER_END_31_SIZE])
            if crc_exp != crc_calc:
                raise Exception(f"Calculated crc '{crc_calc}' does not match sent crc '{crc_exp}'")

        elif self.protocol_version == 3.4:
            data = data_in[TUYA_HEADER_SIZE: -TUYA_HEADER_END_34_SIZE]
            hash_exp, _ = struct.unpack(TUYA_HEADER_END_34_FMT, data_in[-TUYA_HEADER_END_34_SIZE:])
            hash_calc = self.hmac_sha256.hash(data_in[: -TUYA_HEADER_END_34_SIZE])
            if hash_exp != hash_calc:
                raise Exception(f"Calculated hash '{hash_calc}' does not match sent hash '{hash_exp}'")

        # Parse different versions of Tuya packets
        # No data
        if not data:
            data = "{}"

        # Already decoded
        elif data.startswith(b"{"):
            pass

        # Starts with 3.1 version
        elif data.startswith(PROTOCOL_VERSION_BYTES_31):
            data = data[len(PROTOCOL_VERSION_BYTES_31) :]  # remove version header
            # remove (what I'm guessing, but not confirmed is) 16-bytes of MD5 hexdigest of data
            data = self.cipher_ecb_aes128.decrypt(data[16:])

        # Starts with 3.3 version
        elif self.version == 3.3:
            if self.dev_type != "type_0a" or data.startswith(PROTOCOL_VERSION_BYTES_33):
                data = data[len(PROTOCOL_33_HEADER) :]

            data = self.cipher_ecb_aes128.decrypt(data, False)

            if "data unvalid" in data:
                self.dev_type = "type_0d"
                self.logger.debug("switching to dev_type %s", self.dev_type,)
                return None

        # TODO: change 'if' position
        # If version is set to 3.4
        elif self.protocol_version == 3.4:
            # Remove return code from remote if exists
            # Some magic I do not understand why (@https://github.com/harryzz/tuyapi/blob/master/lib/message-parser.js, line 149)
            # Something about stripping return value.
            # Return values are only from devices (remote in my terminology)
            if not (int.from_bytes(data[:4], "big") & 0xFFFFFF00):
                retcode = int.from_bytes(data[:4])
                data = data[4:]

            data = self.cipher_ecb_aes128.decrypt(data, False)
            
            # Remove some sort of version header with some data
            if data.startswith(PROTOCOL_VERSION_BYTES_34):
                data = data[3 + 12:]

            # If there was no data
            if not data:
                data = "{}"
        
        # Unknown format
        else:
            raise Exception(f"Unexpected data={data}")

        if not isinstance(data, str):
            data = data.decode()

        self.logger.debug("Decrypted data: %s", data)

        return TuyaPacket(seqno, cmd, retcode, json.loads(data))


class MessageDispatcher:
    """Buffer and dispatcher for Tuya messages."""

    # Heartbeats always respond with sequence number 0, so they can't be waited for like
    # other messages. This is a hack to allow waiting for heartbeats.
    HEARTBEAT_SEQNO = -100

    def __init__(self, logger, unhandled_packet_callback, tuya_packeter):
        """Initialize a new MessageBuffer."""
        self.logger = logger

        self.buffer = b""
        self.packeter = tuya_packeter

        self.packet_queue = {}
        self.packet_queue_data = {}
        self.unhandled_packet_callback = unhandled_packet_callback

    def abort(self):
        """Abort all waiting clients."""
        for key in self.packet_queue:
            self.packet_queue[key].release()
            del self.packet_queue[key]
            del self.packet_queue_data[key]

    async def wait_for(self, seqno, timeout=5):
        """Wait for response to a sequence number to be received and return it."""
        if seqno in self.packet_queue:
            raise Exception(f"already waiting for packet with seqno '{seqno}'")

        self.logger.debug("Waiting for sequence number %d", seqno)
        self.packet_queue[seqno] = asyncio.Semaphore(0)
        self.packet_queue_data[seqno] = None
        
        try:
            await asyncio.wait_for(self.packet_queue[seqno].acquire(), timeout=timeout)
        except asyncio.TimeoutError:
            del self.packet_queue[seqno]
            del self.packet_queue_data[seqno]
            raise

        self.packet_queue.pop(seqno)
        return self.packet_queue_data.pop(seqno)

    def add_data(self, data):
        """Add new data to the buffer and try to parse messages."""
        self.buffer += data

        while self.buffer:
            # Check if enough data for measage header
            if len(self.buffer) < TUYA_HEADER_RCV_SIZE:
                break

            # Parse header and check if enough data according to length in header
            _, seqno, cmd, length, retcode = struct.unpack_from(TUYA_HEADER_RCV_SIZE, self.buffer)

            # TODO: Not enough data. Should break or raise? (Can missing data come in next TCP packet?)
            if len(self.buffer) - TUYA_HEADER_SIZE < length:
                break

            packet = self.packeter.unpack_message(self.buffer[: TUYA_HEADER_SIZE + length])

            self.buffer = self.buffer[TUYA_HEADER_SIZE + length :]
            self._dispatch(packet)

    def _dispatch(self, packet):
        """Dispatch a message to someone that is listening."""
        self.logger.debug("Dispatching message %s", packet)

        # If there is a listener for this seqn
        if packet.seqno in self.packet_queue:
            self.logger.debug("Dispatching sequence number %d", packet.seqno)
            self.packet_queue_data[packet.seqno] = packet
            self.packet_queue[packet.seqno].release()

        # Display some known messages even though there is no listener for them
        elif packet.cmd == 0x09:
            self.logger.debug("Got heartbeat response (with no listener)")
            if self.HEARTBEAT_SEQNO in self.packet_queue:
                self.packet_queue_data[self.HEARTBEAT_SEQNO] = packet
                self.packet_queue[self.HEARTBEAT_SEQNO].release()

        elif packet.cmd == 0x12:
            self.logger.debug("Got normal updatedps response (with no listener)")
        elif packet.cmd == 0x08:

            self.logger.debug("Got status update (with no listener)")
            self.unhandled_packet_callback(packet)

        else:
            self.logger.debug("Got message type %d for unknown listener %d: %s", packet.cmd, packet.seqno, packet, )


class TuyaListener(ABC):
    """Listener interface for Tuya device changes."""

    @abstractmethod
    def status_updated(self, status):
        """Device updated status."""

    @abstractmethod
    def disconnected(self):
        """Device disconnected."""


class EmptyListener(TuyaListener):
    """Listener doing nothing."""

    def status_updated(self, status):
        """Device updated status."""

    def disconnected(self):
        """Device disconnected."""


class TuyaProtocol(asyncio.Protocol):
    """Implementation of the Tuya protocol."""

    def __init__(self, dev_id, device_key, protocol_version, on_connected, listener):
        """
        Initialize a new TuyaInterface.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            device_key (str, optional): The encryption key. Defaults to None.
        """
        super().__init__()

        # Set up logger that adds device_id to every log
        self.logger = ContextualLogger()
        self.logger.set_logger(_LOGGER, dev_id)

        # self.loop = asyncio.get_running_loop()

        # Future. Async connect (to device) is waiting for this future to return
        self.on_connected = on_connected
                
        self.device_id = dev_id
        self.device_key = device_key.encode("latin1") # TODO: check if needs encoding
        self.protocol_version = protocol_version
        # self.dev_type = "type_0a"

        self.listener = weakref.ref(listener)
        self.packeter = TuyaPacketer(self.device_key, self.protocol_version)
        self.dispatcher = MessageDispatcher(self.device_id, self._status_update, self.packeter)

        self.dps_to_request = {}
        self.dps_cache = {}

        self.seqno = 1000
        
        # Transport from TCP connection (asyncio Transport)
        self.transport = None

        # Heartbeat (async) loop that sends heaartbeat to device every HEARTBEAT_INTERVAL
        self.heartbeater = None


    def _status_update(self, packet):
        if "dps" in packet:
            self.dps_cache.update(packet["dps"])

        # Try to get listener reference and then call status_updated
        listener = self.listener()
        if listener is not None:
            listener.status_updated(self.dps_cache)

    def connection_made(self, transport):
        """Did connect to the device."""

        async def heartbeat_loop():
            """Continuously send heart beat updates."""
            self.logger.debug("Started heartbeat loop")
            while True:
                try:
                    await self.heartbeat()
                    await asyncio.sleep(HEARTBEAT_INTERVAL)
                except asyncio.CancelledError:
                    self.logger.debug("Stopped heartbeat loop")
                    raise
                except asyncio.TimeoutError:
                    self.logger.debug("Heartbeat failed due to timeout, disconnecting")
                    break
                except Exception as ex:  # pylint: disable=broad-except
                    self.logger.exception("Heartbeat failed (%s), disconnecting", ex)
                    break

            transport = self.transport
            self.transport = None
            transport.close()

        self.transport = transport
        self.on_connected.set_result(True)
        self.heartbeater = asyncio.get_running_loop().create_task(heartbeat_loop())

    def data_received(self, data):
        """Received data from device."""
        self.dispatcher.add_data(data)

    def connection_lost(self, exc):
        """Disconnected from device."""
        self.logger.debug("Connection lost: %s", exc)

        try:
            # Try to get listener reference and then call status_updated
            listener = self.listener()
            if listener is not None:
                listener.disconnected()
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("Failed to call disconnected callback")
    
    async def close(self):
        """Close connection and abort all outstanding listeners."""
        self.logger.debug("Closing connection")

        if self.heartbeater is not None:
            self.heartbeater.cancel()
            try:
                await self.heartbeater
            except asyncio.CancelledError:
                pass
            self.heartbeater = None

        if self.dispatcher is not None:
            self.dispatcher.abort()
            self.dispatcher = None

        if self.transport is not None:
            transport = self.transport
            self.transport = None
            transport.close()

    async def exchange(self, command, dps=None):
        """Send and receive a message, returning response from device."""
        self.logger.debug("Sending command %s (device type: %s)", command, self.dev_type,)

        payload = self._generate_payload(command, dps)
        dev_type = self.dev_type

        # Wait for special sequence number if heartbeat
        seqno = MessageDispatcher.HEARTBEAT_SEQNO if command == HEARTBEAT else (self.seqno - 1)

        self.transport.write(payload)
        packet = await self.dispatcher.wait_for(seqno)

        # Perform a new exchange (once) if we switched device type
        if dev_type != self.dev_type:
            self.logger.debug("Re-send %s due to device type change (%s -> %s)", command, dev_type, self.dev_type,)
            return await self.exchange(command, dps)

        return packet.data

    async def status(self):
        """Return device status."""
        # Send status command and get response
        status = await self.exchange(STATUS)

        # If there are any dps (datapoints) data -> update values in dps_cache
        if status and "dps" in status:
            self.dps_cache.update(status["dps"])

        # Return dps_cache
        return self.dps_cache

    async def heartbeat(self):
        """Send a heartbeat message."""
        return await self.exchange(HEARTBEAT)

    async def update_dps(self, dps=None):
        """
        Request device to update index.

        Args:
            dps([int]): list of dps to update, default=detected&whitelisted
        """
        if self.protocol_version == 3.3:
            if dps is None:
                if not self.dps_cache:
                    await self.detect_available_dps()
                if self.dps_cache:
                    dps = [int(dp) for dp in self.dps_cache]
                    # filter non whitelisted dps
                    dps = list(set(dps).intersection(set(UPDATE_DPS_WHITELIST)))

            self.logger.debug("updatedps() entry (dps %s, dps_cache %s)", dps, self.dps_cache)

            payload = self._generate_payload(UPDATEDPS, dps)
            self.transport.write(payload)

        elif self.protocol_version == 3.4:
            raise Exception("TODO")

        return True

    async def set_dp(self, value, dp_index):
        """
        Set value (may be any type: bool, int or string) of any dps index.

        Args:
            dp_index(int):   dps index to set
            value: new value for the dps index
        """
        return await self.exchange(SET, {str(dp_index): value})
    
    async def set_dps(self, dps):
        """Set values for a set of datapoints."""
        return await self.exchange(SET, dps)

    async def detect_available_dps(self):
        """Return which datapoints are supported by the device."""
        # type_0d devices need a sort of bruteforce querying in order to detect the
        # list of available dps experience shows that the dps available are usually
        # in the ranges [1-25] and [100-110] need to split the bruteforcing in
        # different steps due to request payload limitation (max. length = 255)
        self.dps_cache = {}
        ranges = [(2, 11), (11, 21), (21, 31), (100, 111)]

        for dps_range in ranges:
            # dps 1 must always be sent, otherwise it might fail in case no dps is found in the requested range
            self.dps_to_request = {"1": None}
            self.add_dps_to_request(range(*dps_range))
            try:
                data = await self.status()
            except Exception as ex:
                self.logger.exception("Failed to get status: %s", ex)
                raise
            if "dps" in data:
                self.dps_cache.update(data["dps"])

            if self.dev_type == "type_0a":
                return self.dps_cache

        self.logger.debug("Detected dps: %s", self.dps_cache)
        return self.dps_cache
        
    def add_dps_to_request(self, dp_indicies):
        """Add a datapoint (DP) to be included in requests."""
        if isinstance(dp_indicies, int):
            self.dps_to_request[str(dp_indicies)] = None
        else:
            self.dps_to_request.update({str(index): None for index in dp_indicies})

    # This is intended to match requests.json payload at
    # https://github.com/codetheweb/tuyapi :
    # type_0a devices require the 0a command as the status request
    # type_0d devices require the 0d command as the status request, and the list of
    # dps used set to null in the request payload (see generate_payload method)

    # prefix: # Next byte is command byte ("hexByte") some zero padding, then length
    # of remaining payload, i.e. command + suffix (unclear if multiple bytes used for
    # length, zero padding implies could be more than one byte)
    PAYLOAD_DICT = {
        "type_0a": {
            STATUS: {"hexByte": 0x0A, "command": {"gwId": "", "devId": ""}},
            SET: {"hexByte": 0x07, "command": {"devId": "", "uid": "", "t": ""}},
            HEARTBEAT: {"hexByte": 0x09, "command": {}},
            UPDATEDPS: {"hexByte": 0x12, "command": {"dpId": [18, 19, 20]}},
        },
        "type_0d": {
            STATUS: {"hexByte": 0x0D, "command": {"devId": "", "uid": "", "t": ""}},
            SET: {"hexByte": 0x07, "command": {"devId": "", "uid": "", "t": ""}},
            HEARTBEAT: {"hexByte": 0x09, "command": {}},
            UPDATEDPS: {"hexByte": 0x12, "command": {"dpId": [18, 19, 20]}},
        },
    }

    def _generate_payload(self, command, data_in=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data_in(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
        """
        cmd_data = self.PAYLOAD_DICT[self.dev_type][command]
        json_data = cmd_data["command"]
        command_hb = cmd_data["hexByte"]

        if "gwId" in json_data:
            json_data["gwId"] = self.device_id
        if "devId" in json_data:
            json_data["devId"] = self.device_id
        if "uid" in json_data:
            json_data["uid"] = self.device_id  # still use id, no separate uid
        if "t" in json_data:
            json_data["t"] = str(int(time.time()))

        if data_in is not None:
            if "dpId" in json_data:
                json_data["dpId"] = data_in
            else:
                json_data["dps"] = data_in
        elif command_hb == 0x0D:
            json_data["dps"] = self.dps_to_request

        data = json.dumps(json_data).replace(" ", "").encode("utf-8")
        self.logger.debug("Send data: %s", data)

        packet = TuyaPacket(self.seqno, command_hb, 0, data)
        self.seqno += 1
        return self.packeter.pack_message(packet)

async def connect(address, device_id, local_key, protocol_version, listener=None, port=6668, timeout=5,):
    """Connect to a device."""
    loop = asyncio.get_running_loop()
    on_connected = loop.create_future()

    _, protocol = await loop.create_connection(
        lambda: TuyaProtocol(device_id, local_key, protocol_version, on_connected, listener or EmptyListener(), ),
        address,
        port,)

    await asyncio.wait_for(on_connected, timeout=timeout)
    return protocol

class AbstractTuyaAgent(ABC):
    def __init__(self, device_id, device_key):
        self.device_id = device_id
        self.device_key = device_key

        self.datapoints = {}


    @abstractmethod
    def _generate_payload(self):
        """Device updated status."""

    @abstractmethod
    def a(self):
        """Device disconnected."""

class TuyaAgent31(AbstractTuyaAgent):
    def __init__(self, device_id, device_key):
        AbstractTuyaAgent.__init__(device_id, device_key)

class TuyaAgent33(AbstractTuyaAgent):
    def __init__(self, device_id, device_key):
        AbstractTuyaAgent.__init__(device_id, device_key)

class TuyaAgent34(AbstractTuyaAgent):
    def __init__(self, device_id, device_key):
        AbstractTuyaAgent.__init__(device_id, device_key)
