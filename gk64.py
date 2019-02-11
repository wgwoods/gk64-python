#!/usr/bin/python3
# gk64.py - exploration stuff using pyusb to talk to a GK6x keyboard
#
# Copyright (c) 2019 Will Woods <w@wizard.zone>
#
# You shouldn't be using this, because it's horrible, but if you are,
# consider it licensed as GPLv2+. Also, I'm sorry.

import os
import time
import struct

import usb.core
import usb.util

from usb.core import USBError
from collections import namedtuple

import argparse

# unoptimized, translated from http://mdfs.net/Info/Comp/Comms/CRC16.htm
def crc16(data, poly=0x1021, iv=0x0000, xorf=0x0000):
    crc = int(iv)
    for b in bytearray(data):
        crc ^= (b << 8)
        for _ in range(0,8):
            crc <<= 1
            if crc & 0x10000:
                crc = (crc ^ poly) & 0xffff # xor with poly and trunc to 16bit
    return (crc & 0xffff) ^ xorf

def crc16_usb(data, iv=0xffff):
    return crc16(data, poly=0x8005, iv=0xffff, xorf=0xffff)

def mycrc16(data, iv=0xffff):
    return crc16(data, poly=0x1021, iv=0xffff, xorf=0x0000)


def hexdump_line(data):
    linedata = bytearray(data[:16])
    hexbytes = ["%02x" % b for b in linedata] + (["  "] * (16-len(linedata)))
    printable = ''.join(chr(b) if b >= 0x20 and b < 0x7f else '.' for b in linedata)
    return '{}  {}   {} {}'.format(' '.join(hexbytes[:8]),
                                   ' '.join(hexbytes[8:]),
                                   printable[:8],
                                   printable[8:])

def hexdump_iterlines(data, start=0):
    offset = 0
    while offset < len(data):
        yield "{:08x}  {}".format(start+offset,
                                  hexdump_line(data[offset:offset+0x10]))

def hexdump(data, start=0):
    for line in hexdump_iterlines(data, start):
        print(line)

# USB Packet Structure:
#
# Data is usually sent to endpoint 4, and the device answers on endpoint 3.
# In firmware update mode (see below), send to endpoint 2 and get answers on 1.
#
# Outgoing and incoming packets are always 0x64 bytes long, and have roughly
# the same structure. Example outgoing packet data:
#
#   01 01 00 00 00 00 74 1b  00 00 00 00 00 00 00 00   ......t. ........
#   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
#   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
#   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
#
# And the reply:
#
#   01 01 01 00 00 00 35 25  01 39 10 02 09 01 00 00   ......5% .9......
#   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
#   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
#   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
#
# The structure is as follows:
# * 8 byte header, then up to 56 (0x38) bytes of data (padded with zeros)
# * Command header: 01 01 00 00 00 00 74 1b
#   * Byte 0: Command
#   * Byte 1: Subcommand
#   * Byte 2-3: Offset (used for uploading firmware in chunks)
#   * Byte 4: padding? (always 00..)
#   * Byte 5: Size of payload (max 0x38)
#   * Byte 6-7: checksum
#     * CRC16/CCITT-FALSE: little-endian, polynomial 0x1021, IV 0xFFFF
#     * Calculated over the whole 64-byte packet, with checksum = 00 00
#   * Byte 8-63: Payload data, padded with 00s to 64 bytes total

# * Reply header: 01 01 01 00 00 00 35 25
#   * Byte 0: Command
#   * Byte 1: Subcommand
#   * Byte 2: Result - 01 for success, 00 otherwise
#   * Byte 3-5: unused/padding (always 00..)
#   * Byte 6-7: checksum, as above
#   * Byte 8-63: payload (padded to 64 bytes long with 0x00's)
#
# (You'll note that the Reply doesn't seem to tell you how much data it's
# sending you, which makes interpreting the reply a little trickier..)

class BindataMixin(object):
    _struct = None
    @classmethod
    def _unpack(cls, buf):
        return cls(*cls._struct.unpack(buf))
    def _pack(self):
        return self._struct.pack(*self)
    def _hexdump(self):
        data = self._pack()
        size = self._struct.size
        return '\n'.join(hexdump_line(data[s:s+0x10])
                         for s in range(0,size,0x10))
    def _calculate_checksum(self):
        return mycrc16(self._replace(checksum=0)._pack())
    def _replace_checksum(self):
        return self._replace(checksum=self._calculate_checksum())
    def _checksum_ok(self):
        return self.checksum == self._calculate_checksum()

PacketStruct = struct.Struct("<BBHBBH56s")

CommandPacketTuple = namedtuple("CommandPacketTuple", "cmd subcmd offset pad1 length checksum data")
class CommandPacket(CommandPacketTuple, BindataMixin):
    _struct = PacketStruct

ReplyPacketTuple = namedtuple("ReplyPacketTuple", "cmd subcmd result pad1 pad2 checksum data")
class ReplyPacket(ReplyPacketTuple, BindataMixin):
    _struct = PacketStruct

# TODO: document the .bimg header format here!!

BImgHdrTuple = namedtuple("BImgHdrTuple", "magic checksum ts size datachecksum itype name")
class BImgHdr(BImgHdrTuple, BindataMixin):
    _struct = struct.Struct("<IIIIII8s")

class Error(Exception):
    '''Base class for exceptions in this module'''
    pass

class CmdError(Error):
    '''Exception raised when the GK6x reply doesn't indicate success.

    Attributes:
        message: explanation of the error
        reply: the ReplyPacket object
    '''
    def __init__(self, message, reply):
        self.message = message
        self.reply = reply

class FirmwareUpdateError(CmdError):
    '''Exception raised when the GK6x firmware update process fails.'''
    pass

class GK64(object):
    SemitekVendor = 0x1ea7
    WeltrendVendor = 0x040b

    GK64Product = 0x0907
    CDBootProduct = 0x0905

    def __init__(self, bus=None, address=None):
        self.dev = None
        self.cmd_in = None
        self.cmd_out = None
        self.fwid = None
        if bus is None or address is None:
            self.find_dev()

    def __repr__(self):
        return "<{} dev={!r}>".format(self.__class__.__name__, self.dev)

    def find_dev(self):
        self.dev = usb.core.find(idVendor=self.SemitekVendor) or usb.core.find(idVendor=self.WeltrendVendor)
        if self.dev is None:
            return False
        if self.dev.idProduct == self.GK64Product:
            iface = 1
        elif self.dev.idProduct == self.CDBootProduct:
            iface = 0
        else: # TODO: look for the first interface that has an IN endpoint
            iface = 0
        if self.dev.is_kernel_driver_active(iface):
            self.dev.detach_kernel_driver(iface)
        self.cmd_in, self.cmd_out = self.dev[0][iface,0].endpoints()
        return True

    def send_cmd(self, cmd, subcmd, offset=0, length=0, data=None, getreply=True, verbose=False, replytimeout=None):
        if offset & 0xff000000:
            raise ValueError("offset {:#010x} > 0x00ffffff".format(offset))
        if not data:
            data = bytearray(0x38)
        pkt = CommandPacket(cmd, subcmd, offset & 0xffff, offset >> 16, length, 0, data)._replace_checksum()
        if verbose:
            print("send packet:")
            print(pkt._hexdump())
        self.dev.write(self.cmd_out, pkt._pack())
        if not getreply:
            return
        r = ReplyPacket._unpack(self.dev.read(self.cmd_in, 0x40, timeout=replytimeout))
        if verbose:
            print("recv reply:")
            print(r._hexdump())
        return r

    def get_fwid(self):
        r = self.send_cmd(1,1)
        if r.result == 1:
            self.fwid = "{r[3]:02x}-{r[2]:02x}{r[1]:02x}-{r[0]:02x}-V{r[5]:d}.{r[4]:d}".format(r=r.data)
        return self.fwid

    def enter_cdboot_mode(self):
        r = self.send_cmd(3,2)
        time.sleep(1)
        return self.find_dev()

    def enter_keyboard_mode(self):
        self.send_cmd(3,1)
        time.sleep(1)
        return self.find_dev()

    def read_memory_hax(self, offset, verbose=True, replytimeout=None):
        # use my haxed firmware to read arbitrary memory addresses :D
        if offset & 0xff000000:
            raise ValueError("offset {:#010x} > 0x00ffffff".format(offset))
        data = bytearray(0x38)
        pkt = CommandPacket(4, 1, offset & 0xffff, 0, offset >> 16, 0, data)._replace_checksum()
        if verbose:
            print("send packet:")
            print(pkt._hexdump())
        self.dev.write(self.cmd_out, pkt._pack())
        r = ReplyPacket._unpack(self.dev.read(self.cmd_in, 0x40, timeout=replytimeout))
        if verbose:
            print("recv reply:")
            print(r._hexdump())
        retries = 0
        # result == offset works when offset <= 0x00ffffff, but otherwise..
        #while not (r.pad2 == 0x38 and r.result == offset):
        while not (r.pad2 == 0x38):
            if verbose:
                print("retrying...")
            if retries == 0:
                if verbose:
                    print("resend packet:")
                    print(pkt._hexdump())
                    self.dev.write(self.cmd_out, pkt._pack())
            try:
                r = ReplyPacket._unpack(self.dev.read(self.cmd_in, 0x40, timeout=replytimeout))
            except USBError as e:
                if e.errno == 110 and retries <= 5:
                    retries += 1
                    time.sleep(0.05)
                else:
                    raise
            if verbose:
                print("recv reply:")
                print(r._hexdump())
        return r.data

    def cdboot_update_version(self, verdata):
        # the per-keyboard updater sends this after the firmware update but
        # the recovery tool doesn't.
        # Also note that the 8-byte data is the same as what is returned by
        # command 1,8, which is just read from $gp-160...
        #fw_version_sig = bytearray(0x0c, 0x00, 0x12, 0x27,
        #                           0x00, 0x00, 0x6a, 0xf0)
        r = self.send_cmd(2,5, data=verdata)
        if not (r.result == 1 and r.data[:8] == verdata):
            raise FirmwareUpdateError("signature setting failed", r)

    def cdboot_send_firmware(self, bindata, hdr=None):
        if hdr is None:
            # construct an appropriate header
            hdr = make_bimg_header(bindata)
        elif not isinstance(hdr, BImgHdr):
            hdr = BImgHdr._unpack(hdr)

        if not isinstance(hdr, BImgHdr):
            raise ValueError("hdr should be bytes or an instance of BImgHdr")

        # Both updaters do this first, soooo..
        info_r = self.send_cmd(1,2)
        # TODO: use this to verify update later?

        print("sending firmware header: ", end='', flush=True)
        # Both updaters send the header twice and get one (delayed) reply
        self.send_cmd(2,1,data=hdr._pack(), getreply=False)
        r = self.send_cmd(2,1,data=hdr._pack(), replytimeout=10000)
        if r.result != 1:
            raise FirmwareUpdateError(".bimg header not accepted", r)
        print("ok")

        # send firmware one packet-payload (<= 0x38 bytes) at a time
        offset = 0
        print("sending firmware ({:5}/{:5}): ".format(offset, hdr.size),
              end='', flush=True)
        while offset < hdr.size:
            chunk = bindata[offset:offset+0x38] # this might be <0x38 bytes
            size = len(chunk)                   # ...so get the actual size
            r = self.send_cmd(2,2, offset=offset, length=size, data=chunk)
            if r.result != 1:
                raise FirmwareUpdateError("NAK at offset {}".format(offset), r)
            offset += size
            print("\rsending firmware ({:5}/{:5}): ".format(offset, hdr.size),
                  end='', flush=True)
        print("ok")

        # send final timestamp / checksum
        print("sending final packet: ", end='', flush=True)
        final_time = int(time.time())  # TODO: not 100% sure this is right
        final_checksum = 0x1337        # FIXME this is a lie!!
        final_data = struct.pack('<IxxH', final_time, final_checksum)
        r = self.send_cmd(2,3, data=final_data)
        if r.result != 1:
            raise FirmwareUpdateError("firmware final checksum rejected", r)
        print("ok")
        return True

def wait_for_dev():
    print("Looking for device...", flush=True, end='')
    while True:
        try:
            kbd = GK64()
            if kbd.dev is not None:
                kbd.sendcmd(1,2)
                break
        except USBError as e:
            if e.errno == 13: # EPERM
                raise
        time.sleep(0.2)
        print(".", flush=True, end='')
    print(" found {}".format(kbd))
    return kbd

def probe_loop():
    '''
    Yeah, this is gross, but this is just for my personal experimentation..
    '''
    kbd = wait_for_dev()
    results = dict()
    skip_a = [2,3,5,6,7]
    # NOTE: 3:1, 3:2, and 3:3 all seem to reset the system.. but 4 doesn't?
    timeoutcount = 0
    for a in range(1,256):
        for b in range(1,255):
            if a in skip_a: continue

            print("Trying command {:02x}:{:02x}: ".format(a,b), end='', flush=True)

            reply = None
            result = None
            # Send command and save reply (or exception)
            try:
                reply = kbd.sendcmd(a,b)
                result = reply
                timeoutcount = 0
                if any(reply.data):
                    print("reply OK, data:", reply._hexdump())
                elif reply.result == 1:
                    print("reply OK")
                elif reply.result == 0:
                    print("reply NAK")
                else:
                    print("unhandled reply:", reply._hexdump())
            except USBError as err:
                print(err)
                result = err
                if err.errno == 110:
                    timeoutcount += 1

            results[a,b] = result
            if timeoutcount == 3:
                timeoutcount = 0
                skip_a.append(a)
                kbd = wait_for_dev()

            # Check if the device is still available..
            try:
                kbd.sendcmd(1,2)
            except USBError as err:
                # Record that this command lead to an error
                result = [result, err]
                # Wait a moment to recover
                # And reconnect if needed
                if err.errno == 19: # No such device
                    time.sleep(0.2)
                    kbd.find_dev()

            # If we got a good result, show the user
            if reply and (reply.result or any(reply.data)):
                print(reply._hexdump())
                print

    print(results)

def binfile_read(binfile):
    '''Read the data of a (descrambled) firmware image'''
    if os.path.getsize(binfile) > 0xffff:
        raise ValueError(".bin is too big (>64kb)")
    bindata = bytes()
    with open(binfile, 'rb') as binf:
        for idx in range(16):
            vec = binf.read(4)
            if vec[0:2] != b'\x48\x00':
                raise ValueError(".bin doesn't start with a vector table?")
            bindata += vec
        bindata += binf.read()
    return bindata

# These are the values for "magic", "itype", and "name" that I've seen in the
# corresponding file types. "name" doesn't seem to matter for bimg so I'm
# setting it to something recognizable.
# Note that I've got "magic" listed here in big-endian order (because I think
# it was intended that way) but it gets written to the file in little-endian
# order, so the actual first 4 bytes of the header are "1vIB" or "1FMC"...
#
BImgMagic = {
    'bimg': (struct.unpack('>I', b'BIv1')[0], 0x08, b'willrad'),
    'cfg':  (struct.unpack('>I', b'BIv1')[0], 0x04, b''),
    'le':   (struct.unpack('>I', b'CMF1')[0], 0x02, b'LIGHT'),
}

def make_bimg_header(bindata, ts=None, name=None, imgtype='bimg'):
    magic, itype, defname = BImgMagic[imgtype]
    return BImgHdr(magic=magic,
                   checksum=0,
                   ts=ts if ts else int(time.time()),
                   size=len(bindata),
                   datachecksum=mycrc16(bindata),
                   itype=itype,
                   name=name[:7] if name else defname)._replace_checksum()

# TODO: I don't know what the final packet in the firmware update sequence is,
# but here's some examples data I gathered from some packet dumps.
# I've confirmed that these match packets I found in packet dumps. The first
# 32-bit int is definitely just a timestamp, but the 16-bit value is unclear.
# The values are too high to be milliseconds and 16 bits is too small for
# microseconds. It doesn't seem to matter for _uploading_ firmware, at least.
fw_finalize_values = {
    'BBD8': [(0x5beb9290, 0x9677),
             (0x5beb92eb, 0x1049),
    ],
    '7A29': [(0x5c2708c5, 0xbcc0),
             (0x5c27091f, 0x3427),
             (0x5c270934, 0xc28d),
    ]
}

def fw_finalize_packet(ts, cs):
    data = struct.pack("<IxxH",ts,cs)
    return CommandPacket(2,3,0,0,0,0,data)._replace_checksum()

fw_finalize_packets = {fwid:{p:fw_finalize_packet(*p) for p in pairs}
                       for fwid,pairs in fw_finalize_values.items()}


def memaddr(s):
    addr = int(s, 16)
    if addr > 0xffffff:
        raise ValueError
    return addr

def parse_args():
    parser = argparse.ArgumentParser(description='GK6x firmware tool')
    subp = parser.add_subparsers(
        description="(commands marked with a * require modified firmware)")

    fwup = subp.add_parser("fwup", help="send a firmware update")
    fwup.add_argument("action", action="store_const", const="fwup", help=argparse.SUPPRESS)
    fwup.add_argument("binfile", help="firmware binary (w/o header)")
    fwup.add_argument("--header", help="firmware header")

    cmd = subp.add_parser('cmd', help="send command packet")
    cmd.add_argument("action", action="store_const", const="cmd", help=argparse.SUPPRESS)
    cmd.add_argument("cmd", type=int, help="command number")
    cmd.add_argument("sub", type=int, help="sub-command number")

    peek = subp.add_parser('peek', help="* peek at a memory address")
    peek.add_argument("action", action="store_const", const="peek", help=argparse.SUPPRESS)
    peek.add_argument("offset", type=memaddr, help="memory address to peek at")

    dump = subp.add_parser('dump', help="* dump memory to a file")
    dump.add_argument("action", action="store_const", const="dump", help=argparse.SUPPRESS)
    dump.add_argument("start", type=memaddr, help="start address")
    dump.add_argument("end", type=memaddr, help="end address")
    dump.add_argument("outfile", help="output filename")

    args = parser.parse_args()

    return args

def main(args):
    kbd = GK64()
    if args.action == "cmd":
        print(kbd.send_cmd(args.cmd, args.sub)._hexdump())

    elif args.action == "peek":
        hexdump(kbd.read_memory_hax(args.offset), args.offset)

    elif args.action == "dump":
        size = 0x38
        overlap = 0
        offset = args.start
        end = args.end
        with open(args.outfile, 'wb+') as flash_out:
            while offset < end:
                print("hax reading flash: {:#x}".format(offset), end='\n', flush=True)
                # check to make sure we don't read past end, because bad things
                # happen if you read past a memory boundary...
                if (offset + size) >= end:
                    overlap = offset + size - end
                    offset -= overlap
                    assert(offset + size == end)
                chunk = kbd.read_memory_hax(offset)
                if overlap:
                    chunk = chunk[overlap:]
                flash_out.write(chunk)
                offset += len(chunk)
            print()

    elif args.action == "fwup":
        print("reading firmware data: ", end='', flush=True)
        # TODO: checksum while reading
        bindata = binfile_read(args.binfile)
        print("ok, size {}, checksum {:04X}".format(len(bindata), mycrc16(bindata)))
        hdr = None
        if args.header:
            print("reading firmware header: ", end='', flush=True)
            hdrdata = open(args.header,'rb').read(0x20)
            hdr = BImgHdr._unpack(hdrdata)
        else:
            print("building firmware header: ", end='', flush=True)
            hdr = make_bimg_header(bindata)
        print("ok, name='{}', ts={} ({})".format(hdr.name.rstrip(b'\0').decode('utf8'),
                                                 hdr.ts,
                                                 time.strftime("%c", time.gmtime(hdr.ts))))

        # TODO: should have a context manager for CDBOOT mode..
        # FIXME: header will be rejected if we're already in cdboot mode.
        # Gotta reset first...
        print("switching to CDBOOT mode: ", end='', flush=True)
        kbd.enter_keyboard_mode()
        if not kbd.enter_cdboot_mode():
            print("failed :<")
            return
        print("ok")

        try:
            fwup_ok = False
            fwup_ok = kbd.cdboot_send_firmware(bindata, hdr)
        except FirmwareUpdateError as e:
            print("fwup failed: {}".format(e.message))
            print("reply was:")
            print(e.reply._hexdump())
        except OSError as e:
            print("fwup failed: {}".format(e))
        finally:
            print("switching back to keyboard mode: ", end='', flush=True)
            if kbd.enter_keyboard_mode():
                print("ok")
            else:
                print("failed :<")
            if fwup_ok:
                print("firmware updated successfully! have fun!!!!")

if __name__ == '__main__':
    try:
        args = parse_args()
        main(args)
    except KeyboardInterrupt:
        raise SystemExit(1)
    except OSError as e:
        print(e)
        raise SystemExit(e.errno)
