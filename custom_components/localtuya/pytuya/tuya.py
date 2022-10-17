from __future__ import annotations
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
from os import urandom
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

# version_tuple = (9, 0, 0)
# version = version_string = __version__ = "%d.%d.%d" % version_tuple

# Tuya Command Types
# Reference: https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h

# # lan protocol
#define FRM_TP_CFG_WF 1 // only used for ap 3.0 network config
# #define FRM_TP_ACTV 2 // discard
# #define FRM_TP_BIND_DEV 3
# #define FRM_TP_UNBIND_DEV 6
#define FRM_TP_CMD 7
#define FRM_TP_STAT_REPORT 8
#define FRM_TP_HB 9
#define FRM_QUERY_STAT 0x0a
# # define FRM_SSID_QUERY 0x0b // discard
#define FRM_USER_BIND_REQ 0x0c
#define FRM_TP_NEW_CMD 0x0d
#define FRM_ADD_SUB_DEV_CMD 0x0e
#define FRM_CFG_WIFI_INFO 0x0f
#define FRM_QUERY_STAT_NEW 0x10
#define FRM_SCENE_EXEC 0x11
#define FRM_LAN_QUERY_DP 0x12

#define FRM_SECURITY_TYPE3 0x03
#define FRM_SECURITY_TYPE4 0x04
#define FRM_SECURITY_TYPE5 0x05

#define FRM_LAN_EXT_STREAM 0x40
#if defined(ENABLE_LAN_ENCRYPTION) && (ENABLE_LAN_ENCRYPTION==1)
#define FR_TYPE_ENCRYPTION 0x13
#define FRM_AP_CFG_WF_V40 0x14
#define FR_TYPE_BOARDCAST_LPV34 0x23
#endif

# # typedef int AP_CFG_ERR_CODE;
#define AP_CFG_SUCC  0
#define AP_CFG_ERR_PCK  1
#define AP_CFG_AP_NOT_FOUND 2
#define AP_CFG_ERR_PASSWD 3
#define AP_CFG_CANT_CONN_AP 4
#define AP_CFG_DHCP_FAILED 5
#define AP_CFG_CONN_CLOUD_FAILED 6
#define AP_CFG_GET_URL_FAILED 7
#define AP_CFG_GW_ACTIVE_FAILED 8
#define AP_CFG_GW_ACTIVE_SUCCESS 9

# # TinyTuya Error Response Codes
# Reference: https://github.com/jasonacox/tinytuya/blob/master/tinytuya/core.py
# ERR_JSON = 900
# ERR_CONNECT = 901
# ERR_TIMEOUT = 902
# ERR_RANGE = 903
# ERR_PAYLOAD = 904
# ERR_OFFLINE = 905
# ERR_STATE = 906
# ERR_FUNCTION = 907
# ERR_DEVTYPE = 908
# ERR_CLOUDKEY = 909
# ERR_CLOUDRESP = 910
# ERR_CLOUDTOKEN = 911
# ERR_PARAMS = 912
# ERR_CLOUD = 913

_LOGGER = logging.getLogger(__name__)

TuyaPacket = namedtuple("TuyaPacket", "seqno cmd retcode data")

PROTOCOL_VERSION_BYTES_31 = b"3.1"
PROTOCOL_VERSION_BYTES_33 = b"3.3"
PROTOCOL_VERSION_BYTES_34 = b"3.4"

PROTOCOL_33_HEADER = PROTOCOL_VERSION_BYTES_33 + 12 * b"\x00"

SET = "set"
STATUS = "status"
HEARTBEAT = "heartbeat"
CONTROL_NEW = "control_new"
DP_QUERY_NEW = "dp_query_new"
UPDATEDPS = "updatedps"  # Request refresh of DPS

TUYA_HEADER_FMT = ">4I"
TUYA_HEADER_RCV_FMT = ">5I"
TUYA_HEADER_SIZE = struct.calcsize(TUYA_HEADER_FMT)
TUYA_HEADER_RCV_SIZE = struct.calcsize(TUYA_HEADER_RCV_FMT)

TUYA_HEADER_END_31_FMT = ">2I"
TUYA_HEADER_END_34_FMT = ">32sI"
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
        dev_id = self.extra["device_id"].decode()
        return f"|device_id: '{dev_id[0:3]}...{dev_id[-3:]}'| {msg}", kwargs


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

        
class TuyaExtendedLoggingAdapter(logging.LoggerAdapter):
    """Adapter that adds device_id and class to all log points."""

    def process(self, msg, kwargs):
        """Process log point and return output."""
        dev_id = self.extra["device_id"].decode()
        class_name = self.extra["class_name"]
        return f"|device_id: '{dev_id[0:3]}...{dev_id[-3:]}'||{class_name}| {msg}", kwargs


class ExtendedContextualLogger:
    """Contextual logger adding device id to log points."""

    def __init__(self):
        """Initialize a new ContextualLogger."""
        self._logger = None
        self._log = None
        self._device_id = None
        self._class_name = None

    def set_logger(self, logger, device_id, class_name):
        """Set base logger to use."""
        self._log = logger
        self._device_id = device_id
        self._class_name = class_name
        self._logger = TuyaExtendedLoggingAdapter(logger, {"device_id": device_id, "class_name": class_name})

    def copy_logger_for_class(self, class_name):
        """Creates new ExtendedContextualLogger that logs in different class."""
        logger = ExtendedContextualLogger()
        logger.set_logger(self._log, self._device_id, class_name)
        return logger

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

    def __init__(self, logger: ExtendedContextualLogger, key: bytes):
        """Initialize a new AESCipher."""
        self.logger = logger.copy_logger_for_class("AESCipher")
        self.block_size = 16

        self.logger.debug("Creating ECB_AES128 cipher using device_key")
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    def set_session_key(self, session_key: bytes):
        """ """
        self.logger.debug("Changing ECB_AES128 cipher to use session_key")
        self.cipher = Cipher(algorithms.AES(session_key), modes.ECB(), default_backend())

    def encrypt(self, raw: bytes, use_base64: bool=True, padding: bool = True) -> bytes:
        """Encrypt json data to be sent to device."""
        encryptor = self.cipher.encryptor()
        raw = self._pad(raw) if padding is True and len(raw) != 0 else raw
        crypted_text = encryptor.update(raw) + encryptor.finalize()
        return base64.b64encode(crypted_text) if use_base64 else crypted_text

    def decrypt(self, enc: bytes, use_base64: bool=True) -> bytes:
        """Decrypt data from device into json."""
        if use_base64:
            enc = base64.b64decode(enc)

        decryptor = self.cipher.decryptor()
        return self._unpad(decryptor.update(enc) + decryptor.finalize())

    def _pad(self, data: bytes) -> bytes:
        padnum = self.block_size - (len(data) & 0xf)
        return data + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        return data[: -ord(data[len(data) - 1 :])] if len(data) != 0 else b''


class HMAC_SHA256:
    """ """

    def __init__(self, logger: ExtendedContextualLogger, key: bytes):
        self.logger = logger.copy_logger_for_class("HMAC_SHA256")
        self.key = key

    def set_session_key(self, session_key: bytes):
        """ """
        self.logger.debug("Changing HMAC_SHA256 to use session_key")
        self.key = session_key

    def hash(self, data: bytes) -> bytes:
        """ """
        hasher = hmac.HMAC(self.key, hashes.SHA256())
        hasher.update(data)
        return hasher.finalize()


class TuyaPacketer(ABC):
    """ """

    def __init__(self, logger, device_key: bytes):
        self.logger = logger.copy_logger_for_class("TuyaPacketer")
        self.device_key = device_key
        self.cipher_ecb_aes128 = AESCipher(logger, device_key)

    @abstractmethod
    def pack_message(self, packet: TuyaPacket) -> bytes:
        """ """

    @abstractmethod
    def unpack_message(self, data_in: bytes) -> TuyaPacket:
        """ """


class TuyaPacketer31(TuyaPacketer):
    """ """

    def __init__(self, logger, device_key: bytes):
        TuyaPacketer.__init__(self, logger, device_key)

    def pack_message(self, packet: TuyaPacket) -> bytes:
        """Pack a TuyaPacket into bytes."""

        # If prot_version == 3.1 and cmd == SET:
        if packet.cmd == 0x07: # SET command
            encrypted_data = self.cipher_ecb_aes128.encrypt(packet.data)
            to_hash = (b"data=" + encrypted_data + b"||lpv=" + PROTOCOL_VERSION_BYTES_31 + b"||" + self.device_key)
            hasher = md5()
            hasher.update(to_hash)
            hexdigest = hasher.hexdigest()
            encrypted_data = (PROTOCOL_VERSION_BYTES_31 + hexdigest[8:][:16].encode("latin1") + encrypted_data)

        # Create full message excluding CRC and suffix
        buffer = struct.pack(TUYA_HEADER_FMT, TUYA_PREFIX, packet.seqno, packet.cmd, len(encrypted_data) + TUYA_HEADER_END_31_SIZE) + encrypted_data

        # Calculate CRC, add it together with suffix
        buffer += struct.pack(TUYA_HEADER_END_31_FMT, binascii.crc32(buffer), TUYA_SUFFIX)    

        return buffer

    def unpack_message(self, data_in: bytes) -> TuyaPacket:
        """Unpack bytes into a TuyaPacket."""

        # Start with Tuya Header
        # Extract prefix, remote_seq_n, command, len, ret_code from recieved data
        # prefix, seqno, cmd, len, ret
        _, seqno, cmd, _, retcode = struct.unpack(TUYA_HEADER_RCV_FMT, data_in[:TUYA_HEADER_RCV_SIZE])

        # Check CRC/HASH
        data = data_in[TUYA_HEADER_SIZE: -TUYA_HEADER_END_31_SIZE]
        crc_exp, _ = struct.unpack(TUYA_HEADER_END_31_FMT, data_in[-TUYA_HEADER_END_31_SIZE:])
        crc_calc = binascii.crc32(data_in[: -TUYA_HEADER_END_31_SIZE])
        if crc_exp != crc_calc:
            raise Exception(f"Calculated crc '{crc_calc}' does not match sent crc '{crc_exp}'")

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

        # Unknown format
        else:
            raise Exception(f"Unexpected data={data}")

        if not isinstance(data, str):
            data = data.decode()

        self.logger.debug("Decrypted data: %s", data)

        return TuyaPacket(seqno, cmd, retcode, json.loads(data))


class TuyaPacketer33(TuyaPacketer):
    """ """

    def __init__(self, logger, device_key: bytes):
        TuyaPacketer.__init__(self, logger, device_key)

    def pack_message(self, packet: TuyaPacket) -> bytes:
        """Pack a TuyaPacket into bytes."""

        encrypted_data = self.cipher_ecb_aes128.encrypt(packet.data, use_base64=False)
        if packet.command_hb not in [0x0A, 0x12]:
            # add the 3.3 header
            encrypted_data = PROTOCOL_33_HEADER + encrypted_data

        # Create full message excluding CRC and suffix
        buffer = struct.pack(TUYA_HEADER_FMT, TUYA_PREFIX, packet.seqno, packet.cmd, len(encrypted_data) + TUYA_HEADER_END_31_SIZE) + encrypted_data

        # Calculate CRC, add it together with suffix
        buffer += struct.pack(TUYA_HEADER_END_31_FMT, binascii.crc32(buffer), TUYA_SUFFIX)    

        return buffer

    def unpack_message(self, data_in: bytes) -> TuyaPacket:
        """Unpack bytes into a TuyaPacket."""

        # Start with Tuya Header
        # Extract prefix, remote_seq_n, command, len, ret_code from recieved data
        # prefix, seqno, cmd, len, ret
        _, seqno, cmd, _, retcode = struct.unpack(TUYA_HEADER_RCV_FMT, data_in[:TUYA_HEADER_RCV_SIZE])

        # Check CRC/HASH
        data = data_in[TUYA_HEADER_SIZE: -TUYA_HEADER_END_31_SIZE]
        crc_exp, _ = struct.unpack(TUYA_HEADER_END_31_FMT, data_in[-TUYA_HEADER_END_31_SIZE:])
        crc_calc = binascii.crc32(data_in[: -TUYA_HEADER_END_31_SIZE])
        if crc_exp != crc_calc:
            raise Exception(f"Calculated crc '{crc_calc}' does not match sent crc '{crc_exp}'")

        # Parse different versions of Tuya packets
        # No data
        if not data:
            data = "{}"

        # Already decoded
        elif data.startswith(b"{"):
            pass

        # Starts with 3.3 version
        else:
            if self.dev_type != "type_0a" or data.startswith(PROTOCOL_VERSION_BYTES_33):
                data = data[len(PROTOCOL_33_HEADER) :]

            data = self.cipher_ecb_aes128.decrypt(data, False)

            raise Exception("Check if data.decode() is needed")
            if "data unvalid" in data:
                self.dev_type = "type_0d"
                self.logger.debug("switching to dev_type %s", self.dev_type,)
                return None

        if not isinstance(data, str):
            data = data.decode()

        self.logger.debug("Decrypted data: %s", data)

        return TuyaPacket(seqno, cmd, retcode, json.loads(data))


class TuyaPacketer34(TuyaPacketer):
    """ """

    def __init__(self, logger, device_key: bytes):
        TuyaPacketer.__init__(self, logger, device_key)
        self.hmac_sha256 = HMAC_SHA256(logger, device_key)
        self.local_key = None
        self.remote_key = None
        self.session_key = None

    def set_local_key(self, local_key: bytes):
        """Sets the local_key used in calculation of the session_key"""
        self.local_key = local_key

    def set_remote_key(self, remote_key: bytes):
        """Uses remote_key to calculate the session_key"""
        self.remote_key = remote_key

        try:
            self.local_key
        except AttributeError as exc:
            raise Exception("Local_key was not set. Set it before remote_key, so that it can be used in session_key calculation") from exc

        # Calculate session_key
        self.session_key = bytearray()
        for i in range(0x00, 0x10):
            self.session_key.append(self.local_key[i] ^ remote_key[i])
        self.session_key = self.cipher_ecb_aes128.encrypt(self.session_key, use_base64=False, padding=False)

        # From now on the session is used for calculating the Tuya packet hash
        self.cipher_ecb_aes128.set_session_key(self.session_key)
        self.hmac_sha256.set_session_key(self.session_key)


    def pack_message(self, packet: TuyaPacket) -> bytes:
        """Pack a TuyaPacket into bytes."""

        data = packet.data
        if isinstance(data, str):
            data = data.encode("UTF-8")
        encrypted_data = self.cipher_ecb_aes128.encrypt(data, use_base64=False)

        # Create full message excluding hash and suffix
        buffer = struct.pack(TUYA_HEADER_FMT, TUYA_PREFIX, packet.seqno, packet.cmd, len(encrypted_data) + TUYA_HEADER_END_34_SIZE) + encrypted_data
        # Calculate hash, add it together with suffix
        buffer += struct.pack(TUYA_HEADER_END_34_FMT, self.hmac_sha256.hash(buffer), TUYA_SUFFIX)

        return buffer

    def unpack_message(self, data_in: bytes) -> TuyaPacket:
        """Unpack bytes into a TuyaPacket."""

        # Start with Tuya Header
        # Extract prefix, remote_seq_n, command, len, ret_code from recieved data
        # prefix, seqno, cmd, len, ret
        _, seqno, cmd, _, retcode = struct.unpack(TUYA_HEADER_RCV_FMT, data_in[:TUYA_HEADER_RCV_SIZE])

        # Check CRC/HASH
        data = data_in[TUYA_HEADER_SIZE: -TUYA_HEADER_END_34_SIZE]
        hash_exp, _ = struct.unpack(TUYA_HEADER_END_34_FMT, data_in[-TUYA_HEADER_END_34_SIZE:])
        hash_calc = self.hmac_sha256.hash(data_in[: -TUYA_HEADER_END_34_SIZE])
        if hash_exp != hash_calc:
            raise Exception(f"Calculated hash '{hash_calc}' does not match sent hash '{hash_exp}'")

        # Remove return code from remote if exists
        # Some magic I do not understand why (@https://github.com/harryzz/tuyapi/blob/master/lib/message-parser.js, line 149)
        # Something about stripping return value.
        # Return values are only from devices (remote in my terminology)
        # TODO: use struct.unpack?
        if not (int.from_bytes(data[:4], "big") & 0xFFFFFF00):
            retcode = int.from_bytes(data[:4], "big")
            data = data[4:]

        data = self.cipher_ecb_aes128.decrypt(data, use_base64=False)
        
        # Remove some sort of version header with some data
        if data.startswith(PROTOCOL_VERSION_BYTES_34):
            data = data[3 + 12:]
        elif data == b'data format error':
            raise Exception(f"Response (retcode: '{retcode}'): Data format error. TODO: Handle gracefuly")
            # TODO: Handle gracefuly
        
        if not isinstance(data, str) and cmd not in [0x03, 0x04, 0x05]:
            data = data.decode()
            if len(data) == 0:
                self.logger.warning("TODO: Adding '{}' to packet with no data. Is this only quick fix?")
                data = "{}"

            self.logger.debug("Decrypted data: %s", data)

            return TuyaPacket(seqno, cmd, retcode, json.loads(data))
        else:
            self.logger.debug("Decrypted data: %s", data.hex("|"))
            return TuyaPacket(seqno, cmd, retcode, data)


class MessageDispatcher:
    """Buffer and dispatcher for Tuya messages."""

    # Heartbeats always respond with sequence number 0, so they can't be waited for like
    # other messages. This is a hack to allow waiting for heartbeats.
    HEARTBEAT_SEQNO = -100

    def __init__(self, logger: ExtendedContextualLogger, tuya_packeter: TuyaPacketer, parsed_packet_callback ,unhandled_packet_callback):
        """Initialize a new MessageBuffer."""
        self.logger = logger.copy_logger_for_class("MessageDispatcher")
        self.tuya_packeter = tuya_packeter
        self.parsed_packet_callback = parsed_packet_callback
        self.unhandled_packet_callback = unhandled_packet_callback

        self.buffer = b""

        self.packet_queue = {}
        self.packet_queue_data = {}

    def abort(self):
        """Abort all waiting clients."""
        for key in self.packet_queue:
            self.packet_queue[key].release()
            del self.packet_queue[key]
            del self.packet_queue_data[key]

    async def wait_for(self, seqno, timeout=5) -> TuyaPacket:
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

    def add_data(self, data: bytes):
        """Add new data to the buffer and try to parse messages."""
        self.buffer += data

        while self.buffer:
            # Check if enough data for measage header
            if len(self.buffer) < TUYA_HEADER_RCV_SIZE:
                break

            # Parse header and check if enough data according to length in header
            # prefix, seqno, cmd, len, ret
            _, _, _, length, _ = struct.unpack_from(TUYA_HEADER_RCV_FMT, self.buffer)

            # TODO: Not enough data. Should break or raise? (Can missing data come in next TCP packet?)
            if len(self.buffer) - TUYA_HEADER_SIZE < length:
                break

            packet = self.tuya_packeter.unpack_message(self.buffer[: TUYA_HEADER_SIZE + length])

            self.buffer = self.buffer[TUYA_HEADER_SIZE + length :]
            self.parsed_packet_callback(packet)
            self._dispatch(packet)

    def _dispatch(self, packet: TuyaPacket):
        """Dispatch a message to someone that is listening."""
        self.logger.debug("Dispatching message %s", packet)

        # If there is a listener for this seqn
        if packet.seqno in self.packet_queue:
            self.logger.debug("Dispatching sequence number %d", packet.seqno)
            self.packet_queue_data[packet.seqno] = packet
            self.packet_queue[packet.seqno].release()

        # Display some known messages even though there is no listener for them TODO: call callback for every unhandeled packet
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
            self.logger.debug("Got message with command '%x' for unknown listener %d: %s", packet.cmd, packet.seqno, packet, )
            self.unhandled_packet_callback(packet)


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

    def __init__(self, logger: ExtendedContextualLogger, device_key: bytes, protocol_version: float, connection_made_callback, connection_lost_callback, unhandled_packet_callback):
        """
        Initialize a new TuyaInterface.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            device_key (str, optional): The encryption key. Defaults to None.
        """
        super().__init__()

        self.logger = logger.copy_logger_for_class("TuyaProtocol")

        # self.dev_type = "type_0a"
        # Will get set with first incomming packet
        # TODO: may not work with Tuya protocol v3.1 & v3.3!
        self.remote_seqno = None

        if protocol_version == 3.1:
            self.packeter = TuyaPacketer31(logger, device_key)
        elif protocol_version == 3.3:
            self.packeter = TuyaPacketer33(logger, device_key)
        elif protocol_version == 3.4:
            self.packeter = TuyaPacketer34(logger, device_key)
        else:
            raise Exception(f"Unknown Protocol version '{protocol_version}'")
        
        self.dispatcher = MessageDispatcher(logger, self.packeter, self.parsed_packet_callback, unhandled_packet_callback)

        self.connection_made_callback = connection_made_callback
        self.connection_lost_callback = connection_lost_callback

        # Transport from TCP connection (asyncio Transport)
        self.transport = None

    def connection_made(self, transport: asyncio.BaseTransport):
        """Did connect to the device."""
        self.transport = transport
        self.connection_made_callback()

    def data_received(self, data: bytes):
        """Received data from device."""
        self.dispatcher.add_data(data)

    def parsed_packet_callback(self, data):
        """ Callback that keeps track of the remote_seqno so it knows what seqno to wait for when calling exchange()."""
        self.remote_seqno = data.seqno

    def connection_lost(self, exc):
        """
        Disconnected from device.
        
        The heartbeat will time out and throw exception that is immediately caught -> stopping heartbeat_loop
        """
        self.logger.debug("Connection lost: %s", exc)
        self.connection_lost_callback()
    
    async def close(self):
        """Close connection and abort all outstanding listeners."""
        self.logger.debug("Closing protocol connection")

        if self.dispatcher is not None:
            self.dispatcher.abort()
            self.dispatcher = None

        if self.transport is not None:
            transport = self.transport
            self.transport = None
            transport.close()

    async def exchange(self, packet: TuyaPacket, seqno: int = None) -> TuyaPacket:
        """Send and receive a message, returning response from device."""
        # Wait for special sequence number if heartbeat
        seqno = MessageDispatcher.HEARTBEAT_SEQNO if packet.cmd == 0x09 else seqno

        packet_raw = self.packeter.pack_message(packet)
        self.transport.write(packet_raw)

        if seqno is not None:
            packet = await self.dispatcher.wait_for(seqno)
        else:
            packet = await self.dispatcher.wait_for(self.remote_seqno + 1)
        return packet

    async def send(self, packet: TuyaPacket):
        """Send a message and do not wait for response."""
        # Wait for special sequence number if heartbeat

        packet_raw = self.packeter.pack_message(packet)
        self.transport.write(packet_raw)


class AbstractTuyaAgent(ABC):
    """ """

    # TODO: Will EmptyListener get immediately destroyed?
    def __init__(self, device_id: bytes, device_key: bytes, listener: TuyaListener):
        self.logger = ExtendedContextualLogger()
        self.logger.set_logger(_LOGGER, device_id, "TuyaAgent")
        self.logger.debug("TuyaAgent __init__()")

        if isinstance(device_id, str):
            device_id = device_id.encode()

        if isinstance(device_key, str):
            device_key = device_key.encode()
        
        self.device_id = device_id
        self.device_key = device_key
        # self.device_key = device_key.encode("latin1") # TODO: check if needs encoding
        self.dev_type = "type_0a"

        self.datapoints_cache = {}
        self.datapoints_to_request = {}
        self.seqno = 1000

        self.listener = weakref.ref(listener)
        # Heartbeat (async) loop that sends heaartbeat to device every HEARTBEAT_INTERVAL
        self.heartbeater = None

        self.protocol = None

        # Load available commands from commands.json file
        path = os.path.join(os.path.dirname(__file__), "commands.json")
        f = open(path, encoding='UTF-8')
        self.device_command_list = json.load(f)
        f.close()

        # Load available datapoints from commands.json file
        path = os.path.join(os.path.dirname(__file__), "datapoints.json")
        f = open(path, encoding='UTF-8')
        self.device_datapoints = json.load(f)
        f.close()


    def _unhandled_packet_callback(self, packet):
        if "dps" in packet:
            self.datapoints_cache.update(packet["dps"])

        # Try to get listener reference and then call status_updated
        listener = self.listener()
        if listener is not None:
            listener.status_updated(self.datapoints_cache)
    

    def _start_heartbeat(self):
        async def heartbeat_loop():
            """Continuously send heart beat updates."""
            self.logger.debug("Started heartbeat loop")

            # Delay the first heartbeat because of tuya protocol v3.4. Wait a while after session_key handshake
            await asyncio.sleep(5)
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
            
            # Timeout or other exception (excluding asyncio.CancelledError) -> disconnect device
            self.close()

        self.heartbeater = asyncio.get_running_loop().create_task(heartbeat_loop())
        
    async def exchange(self, command, dps=None) -> dict | bytes:
        """Send and receive a message, returning response from device."""
        self.logger.debug("Sending command %s (device type: %s)", command, self.dev_type,)

        packet_out = self._generate_payload(command)
        dev_type = self.dev_type

        packet_response = await self.protocol.exchange(packet_out)

        # Perform a new exchange (once) if we switched device type
        if dev_type != self.dev_type:
            self.logger.debug("Re-send %s due to device type change (%s -> %s)", command, dev_type, self.dev_type,)
            return await self.exchange(command, dps).data

        return packet_response.data

    async def heartbeat(self):
        """Send a heartbeat message."""
        return await self.exchange(HEARTBEAT)
        
    async def status(self) -> dict:
        """Return device status."""
        # Send status command and get response
        status = await self.exchange(STATUS)

        # If there are any dps (datapoints) data -> update values in datapoints_cache
        if status and "dps" in status:
            self.datapoints_cache.update(status["dps"])

        # Return datapoints_cache
        return self.datapoints_cache

    def _on_connected(self):
        """Callback after getting connected to the device."""
        self._start_heartbeat()

    def _on_disconnected(self):
        """Callback after getting disconnected from the device."""
        try:
            # Try to get listener reference and then call status_updated
            listener = self.listener()
            if listener is not None:
                listener.disconnected()
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("Failed to call disconnected callback")

    async def disconnect(self):
        """Disconnect and abort all outstanding listeners."""
        self.logger.debug("Closing connection")

        if self.heartbeater is not None:
            self.heartbeater.cancel()
            try:
                await self.heartbeater
            except asyncio.CancelledError:
                pass
            self.heartbeater = None

        # Closes (TCP) transport and aborts all outstanding listeners
        await self.protocol.close()

    @abstractmethod
    async def update_dps(self, datapoints: list[int]=None) -> bool:
        """ """

    @abstractmethod
    async def set_dp(self, value: str | int | bool, dp_index: int=None) -> dict:
        """ """
        
    @abstractmethod
    async def set_dps(self, data: dict[str, str | int | bool]=None) -> dict:
        """ """

    @abstractmethod
    async def detect_available_dps(self) -> dict:
        """ """

    @abstractmethod
    def add_dps_to_request(self, datapoints: int | list):
        """ """
        
    @abstractmethod
    def _generate_payload(self, command: str, data_in: str=None) -> TuyaPacket:
        """Generate TuyaPacket to be sent by Tuya protocol."""

    @abstractmethod
    async def connect(self, address: str, port: int, timeout,):
        """Used to connect to the device."""

    async def _connect(self, address: str, device_key: bytes, protocol_version: float, port: int, timeout,):
        """Connect to a device."""
        if self.protocol is not None:
            raise Exception("Device is already connected!")

        self.logger.debug(f"Connecting to device at '{address}:{port}' with protocol v{protocol_version}")

        loop = asyncio.get_running_loop()

        _, protocol = await loop.create_connection(
            lambda: TuyaProtocol(self.logger, device_key, protocol_version, lambda: None, self._on_disconnected, self._unhandled_packet_callback),
            address,
            port,)

        self.protocol = protocol

        # self._on_connected()

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
        await self.protocol.close()

class TuyaAgent31(AbstractTuyaAgent):
    """ """
    
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

    def __init__(self, device_id: bytes, device_key: bytes, listener: TuyaListener=None):
        AbstractTuyaAgent.__init__(self, device_id, device_key, listener or EmptyListener())

    async def update_dps(self, command: str, data_in: str=None) -> bool:
        """
        Request device to update index.

        Args:
            dps([int]): list of dps to update, default=detected&whitelisted
        """
        # TODO: This is from rewriten code, I do not have v3.1 and v3.3 devices
        self.logger.warning("Cannot use update_dps with Tuya Protocol v3.1. I do not have v3.1 device and cannot check if v3.1 has the 'UPDATEDPS' command.")
        return False

    async def set_dp(self, value: str | int | bool, dp_index: int=None) -> dict:
        """
        Set value (may be any type: bool, int or string) of any dps index.

        Args:
            dp_index(int):   dps index to set
            value: new value for the dps index
        """
        self.logger.warning("Cannot check Tuya Protocol v3.1.")
        return await self.exchange(SET, {str(dp_index): value})
    
    async def set_dps(self, data: dict[str, str | int | bool]=None) -> dict:
        """Set values for a set of datapoints."""
        self.logger.warning("Cannot check Tuya Protocol v3.1.")
        return await self.exchange(SET, data)

    async def detect_available_dps(self) -> dict:
        """Return which datapoints are supported by the device."""
        # type_0d devices need a sort of bruteforce querying in order to detect the
        # list of available dps experience shows that the dps available are usually
        # in the ranges [1-25] and [100-110] need to split the bruteforcing in
        # different steps due to request payload limitation (max. length = 255)
        self.logger.warning("Cannot check Tuya Protocol v3.1.")
        self.datapoints_cache = {}
        ranges = [(2, 11), (11, 21), (21, 31), (100, 111)]

        for dps_range in ranges:
            # dps 1 must always be sent, otherwise it might fail in case no dps is found in the requested range
            self.datapoints_to_request = {"1": None}
            self.add_dps_to_request(range(*dps_range))
            try:
                data = await self.status()
            except Exception as ex:
                self.logger.exception("Failed to get status: %s", ex)
                raise
            if "dps" in data:
                self.datapoints_cache.update(data["dps"])

            if self.dev_type == "type_0a":
                return self.datapoints_cache

        self.logger.debug("Detected datapoints: %s", self.datapoints_cache)
        return self.datapoints_cache
        
    def add_dps_to_request(self, datapoints: int | list):
        """Add a datapoint (DP) to be included in requests."""
        self.logger.warning("Cannot check Tuya Protocol v3.1.")
        if isinstance(datapoints, int):
            self.datapoints_to_request[str(datapoints)] = None
        else:
            self.datapoints_to_request.update({str(index): None for index in datapoints})

    def _generate_payload(self, command: str, data_in: str=None) -> TuyaPacket:
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data_in(dict, optional): The data to be send.
                This is what will be passed via the 'dps' entry
        """
        self.logger.warning("Cannot check Tuya Protocol v3.1.")
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
            json_data["dps"] = self.datapoints_to_request

        data = json.dumps(json_data).replace(" ", "").encode("utf-8")
        self.logger.debug("Send data: %s", data)

        packet = TuyaPacket(self.seqno, command_hb, 0, data)
        self.seqno += 1
        return packet

    async def connect(self, address: str, port: int=6668, timeout=5,):
        await super()._connect(address, self.device_key, 3.1, port, timeout)


class TuyaAgent33(TuyaAgent31):
    """ """

    def __init__(self, device_id: bytes, device_key: bytes, listener: TuyaListener=None):
        TuyaAgent31.__init__(self, device_id, device_key, listener or EmptyListener())

    async def update_dps(self, dps=None):
        """
        Request device to update index.

        Args:
            dps([int]): list of dps to update, default=detected&whitelisted
        """
        self.logger.warning("Cannot check Tuya Protocol v3.3.")
        if dps is None:
            if not self.datapoints_cache:
                await self.detect_available_dps()
            if self.datapoints_cache:
                dps = [int(dp) for dp in self.datapoints_cache]
                # filter non whitelisted datapoints
                dps = list(set(dps).intersection(set(UPDATE_DPS_WHITELIST)))

        self.logger.debug("update_dps() entry (dps %s, datapoints_cache %s)", dps, self.datapoints_cache)

        packet = self._generate_payload(UPDATEDPS, dps)
        await self.protocol.send(packet)

        return True

    async def connect(self, address: str, port: int=6668, timeout=5,):
        await super()._connect(address, self.device_key, 3.3, port, timeout)


class TuyaAgent34(AbstractTuyaAgent):
    """ """

    def __init__(self, device_id: bytes, device_key: bytes, listener: TuyaListener=None):
        AbstractTuyaAgent.__init__(self, device_id, device_key, listener or EmptyListener())
        self.local_seqno = 12101
        self.remote_seqno = None
        self.local_key = urandom(16)
        self.remote_key = None

        self.wait_for_remote_key_future = asyncio.get_running_loop().create_future()

    async def connect(self, address: str, port: int=6668, timeout=5,):
        await super()._connect(address, self.device_key, 3.4, port, timeout)

        packet = TuyaPacket(self.local_seqno, self.device_command_list["commands_3.4"]["SEND_LOCAL_KEY"], 0, self.local_key)
        self.local_seqno += 1
        await self.protocol.send(packet)
    
        await self.wait_for_remote_key_future

        packet = TuyaPacket(self.local_seqno, self.device_command_list["commands_3.4"]["SEND_REMOTE_KEY"], 0, self.protocol.packeter.hmac_sha256.hash(self.remote_key))
        self.local_seqno += 1
        await self.protocol.send(packet)

        # Set local_key and then remote_key -> packer34 generates session_key and updates ECB_AES128 cipher with session_key
        self.protocol.packeter.set_local_key(self.local_key)
        self.protocol.packeter.set_remote_key(self.remote_key)

        self.logger.debug(f"Device_key: {self.device_key}")
        self.logger.debug(f"Local_key: {self.local_key.hex()}")
        self.logger.debug(f"Remote_key: {self.remote_key.hex()}")

        await asyncio.sleep(2)

        packet = TuyaPacket(self.local_seqno, self.device_command_list["commands_3.4"]["DP_QUERY_NEW"], 0, "{}")
        self.local_seqno += 1
        await self.protocol.send(packet)

        await asyncio.sleep(2)

        # Gained access to the device after handshake -> can call AbstractTuyaAgent._on_connected() -> starts sending heartbeat
        AbstractTuyaAgent._on_connected(self)

    def _unhandled_packet_callback(self, packet):
        # Keep track of the remote_seqno
        self.remote_seqno = packet.seqno
        self.logger.debug(f"Got unhandled packet seqno: [{packet.seqno}], cmd: [{packet.cmd}], data: [{packet.data}]")

        if packet.cmd == 0x04:
            # TODO: Compare received HMAC_SHA256 of the local_key (calculate from local_key and compare)
            # calc_hash_of_local_key = ...
            exp_hash_of_local_key = packet.data[-32:]
            # if exp_hash_of_local_key != calc_hash_of_local_key: ....

            self.remote_key = packet.data[:16]
            self.wait_for_remote_key_future.set_result(True)

        return super()._unhandled_packet_callback(packet)

    async def heartbeat(self):
        """Send a heartbeat message."""
        return await self.exchange(self._generate_payload(HEARTBEAT))

    async def status(self) -> dict:
        """Return device status."""
        # TODO: Is this alright?
        await self.update_dps()
        return self.datapoints_cache

    def _on_connected(self):
        """Callback after getting connected to the device."""
        # Overwrite base _on_connected, all is handled in self.connect() because of the key generation
        # Do nothing, all is done in self.connect()

    async def exchange(self, packet_out: TuyaPacket) -> dict | bytes:
        """Send and receive a message, returning response from device."""
        self.logger.debug(f"Sending packet {packet_out}")

        packet_response = await self.protocol.exchange(packet_out)

        return packet_response.data
        
    async def update_dps(self, datapoints: list[int]=None) -> bool:
        """ """        
        packet = self._generate_payload(DP_QUERY_NEW)

        if datapoints is not None:
            self.logger.warning("TODO: DP_QUERY_NEW should not have any data in. Can it have?")

        data = await self.exchange(packet)
        dps_status = data["dps"]
        self.datapoints_cache.update(dps_status)

        self.logger.debug(f"Updated datapoints_cache: {self.datapoints_cache}")

        return True

    async def set_dp(self, value: str | int | bool, dp_index: int) -> dict:
        """ """
        return await self.exchange(self._generate_payload(CONTROL_NEW, {str(dp_index): value}))
        
    async def set_dps(self, data: dict[str, str | int | bool]=None) -> dict:
        """ data is a dict of 'dp_id : value'."""
        return await self.exchange(self._generate_payload(CONTROL_NEW, data))

    async def detect_available_dps(self) -> dict:
        """ """
        if await self.update_dps() is True:
            return self.datapoints_cache
        else:
            # TODO: Handle gracefuly
            raise Exception("Unable to detect available dps. TODO: Handle gracefuly")

    def add_dps_to_request(self, datapoints: int | list):
        """ """
        # TODO: Is this alright?
        self.logger.warning("TODO: Can it be empty for protocol v3.4? detect_available_dps queries all.")

    def list_available_datapoints(self, device_name: str):
        """Uses info from datapoints.json (generated from Tuya cloud API)."""
        print(f"Showing datapoint for '{device_name}':")
        for datapoints in self.get_datapoints(device_name):
            print(f"    {datapoints}")

    def get_available_datapoints(self, device_name: str) -> list[str]:
        """Uses info from datapoints.json (generated from Tuya cloud API)."""
        datapoints = [dp for dp in self.device_datapoints[device_name]["functions"]]
        return datapoints

    def _generate_payload(self, command: str, data_in: str=None) -> TuyaPacket:
        """ """
        if command == HEARTBEAT:
            return self._create_tuya_packet_helper("HEART_BEAT")

        elif command == DP_QUERY_NEW:
            if data_in is not None:
                self.logger.warning("DP_QUERY_NEW should not have any data in. TODO: can it have?")
            return self._create_tuya_packet_helper("DP_QUERY_NEW", "{}")

        elif command == CONTROL_NEW:
            data = {"data": {"dps": data_in}, "protocol": 5, "t": str(int(time.time() * 1000))}
            msg = b'3.4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            msg += json.dumps(data).replace(" ", "").encode("utf-8")
            return self._create_tuya_packet_helper("CONTROL_NEW", msg)

        else:
            raise Exception("TODO: _generate_payload")

    def _create_tuya_packet_helper(self, command: str, data: bytes = b"") -> TuyaPacket:
        """ Creates Tuya packet and increments the local_seqno. """
        packet = TuyaPacket(self.local_seqno, self.device_command_list["commands_3.4"][command], 0, data)
        self.local_seqno += 1
        return packet