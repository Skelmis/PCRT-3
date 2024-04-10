# -*- coding:utf-8 -*-
__author__ = "sherlly"
__version__ = "1.1"

import zlib
import struct
import re
import os
import argparse
import itertools
import platform
import sys

if platform.system() == "Windows":
    import ctypes

    STD_OUTPUT_HANDLE = -11
    FOREGROUND_BLUE = 0x09
    FOREGROUND_GREEN = 0x0A
    FOREGROUND_RED = 0x0C
    FOREGROUND_SKYBLUE = 0x0B
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

    def set_cmd_text_color(color, handle=std_out_handle):
        status = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
        return status

    def reset_color():
        set_cmd_text_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

    def print_red(message):
        set_cmd_text_color(FOREGROUND_RED)
        sys.stdout.write(message)
        reset_color()

    def print_sky_blue(message):
        set_cmd_text_color(FOREGROUND_SKYBLUE)
        sys.stdout.write(message)
        reset_color()

    def print_green(message):
        set_cmd_text_color(FOREGROUND_GREEN)
        sys.stdout.write(message)
        reset_color()


def str2hex(s: bytes | int) -> str:
    # Program checks against known upper case
    # for basically everything lol
    if isinstance(s, bytes):
        return s.hex().upper()

    elif isinstance(s, int):
        # https://stackoverflow.com/a/2269841
        # No prefix in this cos others add it as required
        return "%X" % s

    raise ValueError(f"{s.__class__.__name__} is not supported")


def int2hex(i):
    return "0x" + hex(i)[2:].upper()


def str2num(s, n=0):
    if n == 4:
        return struct.unpack("!I", s)[0]
    else:
        return eval("0x" + str2hex(s))


def write_file(filename):
    if os.path.isfile(filename) is True:
        os.remove(filename)
    file = open(filename, "wb+")
    return file


def read_file(filename):
    try:
        with open(filename, "rb") as file:
            data = file.read()
    except IOError as error:
        print(termcolor("Error", error[1] + ": " + filename))
        raise error
    return data


def termcolor(flag, sentence):
    # check platform
    system = platform.system()
    if system == "Linux" or system == "Darwin":
        if flag == "Notice":
            return "\033[0;34m[%s]\033[0m %s" % (flag, sentence)
        elif flag == "Detected":
            return "\033[0;32m[%s]\033[0m %s" % (flag, sentence)
        elif flag == "Error" or flag == "Warning" or flag == "Failed":
            return "\033[0;31m[%s]\033[0m %s" % (flag, sentence)
    elif system == "Windows":
        try:
            import ctypes

            if flag == "Notice":
                print_sky_blue("[%s] " % flag)
                return sentence
            elif flag == "Detected":
                print_green("[%s] " % flag)
                return sentence
            elif flag == "Error" or flag == "Warning" or flag == "Failed":
                print_red("[%s] " % flag)
                return sentence
        except ImportError as error:
            print("[Error]", error)
            print("Using the normal color to show...")
            return "[%s] %s" % (flag, sentence)
    else:
        return "[%s] %s" % (flag, sentence)


# noinspection PyMethodMayBeStatic,PyShadowingNames,PyAttributeOutsideInit,PyPep8Naming,SpellCheckingInspection
class PNG(object):

    def __init__(self, in_file="", out_file="output.png", choices="", mode=0):
        self.in_file = in_file
        self.out_file = out_file
        self.choices = choices
        self.i_mode = mode

    def __del__(self):
        try:
            self.file.close()
        except AttributeError:
            pass

    def add_payload(self, name: str, payload: str, way):
        # allow newlines for payloads
        payload = payload.replace("\\n", "\n")

        data = self.load_png()
        if data == -1:
            return -1
        self.file = write_file(self.out_file)
        if way == 1:
            # way1:add ancillary
            payload_chunk = self.make_ancillary(name, payload)
            pos = data.find("IHDR".encode())
            self.file.write(data[: pos + 21])
            self.file.write(payload_chunk)
            self.file.write(data[pos + 21 :])  # noqa
        elif way == 2:
            # way2:add critical chunk:IDAT
            name = "IDAT"
            payload_chunk = self.make_critical(name, payload)
            pos = data.find("IEND".encode())
            self.file.write(data[: pos - 4])
            self.file.write(payload_chunk)
            self.file.write(data[pos - 4 :])  # noqa

    def make_critical(self, name, payload) -> bytes:
        print(termcolor("Notice", "Payload chunk name: %s" % name))
        payload: bytes = zlib.compress(payload)
        length = len(payload)
        out = (name + payload).encode()
        crc = zlib.crc32(out) & 0xFFFFFFFF
        data = struct.pack(f"!I4s{length}sI", length, name.encode(), payload, crc)
        return data

    def make_ancillary(self, name, payload) -> bytes:
        if name is None:
            name = self.ran_ancillary_name()
        name = name[0].lower() + name[1:4].upper()
        print(termcolor("Notice", "Payload chunk name: %s" % name))
        length = len(payload)
        out = (name + payload).encode()
        crc = zlib.crc32(out) & 0xFFFFFFFF
        # Struct packing
        # 4s -> name is == len 4
        # {length}s -> payload string
        data = struct.pack(
            f"!I4s{length}sI",
            length,
            name.encode(),
            payload.encode(),
            crc,
        )
        return data

    def ran_ancillary_name(self):
        import random
        import string

        name = "".join(random.sample(string.ascii_lowercase, 4))
        return name

    def get_pic_info(self, ihdr=""):
        """
        bits: color depth
        mode: 0:gray[1] 2:RGB[3] 3:Indexed[1](with palette) 4:grey & alpha[2] 6:RGBA[4]
        compression: DEFLATE(LZ77+Huffman)
        filter: 0:None 1:sub X-A 2:up X-B 3:average X-(A+B)/2 4:Paeth p = A + B − C
        C B D
        A X
        """
        data = self.load_png()
        if data == -1:
            return -1
        if ihdr == "":
            pos, IHDR = self.find_ihdr(data)
            if pos == -1:
                print(termcolor("Detected", "Lost IHDR chunk"))
                return -1
            length = struct.unpack("!I", IHDR[:4])[0]
            ihdr = IHDR[8 : 8 + length]  # noqa

        (
            self.width,
            self.height,
            self.bits,
            self.mode,
            self.compression,
            self.filter,
            self.interlace,
        ) = struct.unpack("!iiBBBBB", ihdr)

        self.interlace = str2num(ihdr[12])
        if self.mode == 0 or self.mode == 3:  # Gray/Index
            self.channel = 1
        elif self.mode == 2:  # RGB
            self.channel = 3
        elif self.mode == 4:  # GA
            self.channel = 2
        elif self.mode == 6:  # RGBA
            self.channel = 4
        else:
            self.channel = 0

        data = self.load_png()
        if data == -1:
            return -1
        self.content = self.find_ancillary(data)

    def print_pic_info(self):
        status = self.get_pic_info()
        if status == -1:
            return -1

        mode_dict = {
            0: "Grayscale",
            2: "RGB",
            3: "Indexed",
            4: "Grayscale with Alpha",
            6: "RGB with Alpha",
        }
        compress_dict = {0: "Deflate"}
        filter_dict = {0: "None", 1: "Sub", 2: "Up", 3: "Average", 4: "Paeth"}
        interlace_dict = {0: "Noninterlaced", 1: "Adam7 interlaced"}
        print(
            "\n-------------------------"
            "Image Infomation------------"
            "---------------------------"
        )
        print(
            "Image Width: %d\nImage Height: %d\nBit Depth: %d\nChannel: %d"
            % (self.width, self.height, self.bits, self.channel)
        )
        print("ColorType: %s" % (mode_dict[self.mode]))
        print(
            "Interlace: %s\nFilter method: %s\nCompression method: %s"
            % (
                interlace_dict[self.interlace],
                filter_dict[self.filter],
                compress_dict[self.compression],
            )
        )
        print("Content: ")
        for k in self.content:
            if self.content[k]:
                text_t = "\n".join(self.content[k]).split("\n")
                text = ""
                import re

                for t in text_t:
                    if re.match(r"^ +$", t):
                        pass
                    else:
                        text += "\n" + t
                print("%s: " % k, text)
        print(
            "----------------------------------"
            "----------------------------------------------\n"
        )

    def clear_filter(self, idat, width, height, channel, bits=8):
        IDAT = ""
        if len(idat) == height * width * channel:
            return idat
        filter_unit = bits / 8 * channel
        for i in range(0, len(idat), width * channel + 1):
            line_filter = str2num(idat[i])
            idat_data = idat[i + 1 : i + width * channel + 1]  # noqa
            if i >= 1:
                idat_data_u = tmp
            else:
                idat_data_u = [0] * width * channel

            if line_filter not in [0, 1, 2, 3, 4]:
                return -1

            if line_filter == 0:  # None
                tmp = list(idat_data)
                IDAT += "".join(tmp)

            elif line_filter == 1:  # Sub
                k = 0
                tmp = list(idat_data)
                for j in range(filter_unit, len(idat_data)):
                    tmp[j] = chr((ord(idat_data[j]) + ord(tmp[k])) % 256)
                    k += 1
                IDAT += "".join(tmp)

            elif line_filter == 2:  # Up
                tmp = ""
                for j in range(len(idat_data)):
                    tmp += chr((ord(idat_data[j]) + ord(idat_data_u[j])) % 256)
                IDAT += tmp
                tmp = list(tmp)

            elif line_filter == 3:  # Average
                tmp = list(idat_data)
                k = -filter_unit
                for j in range(len(idat_data)):
                    if k < 0:
                        a = 0
                    else:
                        a = ord(tmp[k])
                    tmp[j] = chr(
                        (ord(idat_data[j]) + (a + ord(idat_data_u[j])) / 2) % 256
                    )
                    k += 1
                IDAT += "".join(tmp)

            elif line_filter == 4:  # Paeth

                def predictor(a, b, c):
                    """a = left, b = above, c = upper left"""
                    p = a + b - c
                    pa = abs(p - a)
                    pb = abs(p - b)
                    pc = abs(p - c)
                    if pa <= pb and pa <= pc:
                        return a
                    elif pb <= pc:
                        return b
                    else:
                        return c

                k = -filter_unit
                tmp = list(idat_data)
                for j in range(len(idat_data)):
                    if k < 0:
                        a = c = 0
                    else:
                        a = ord(tmp[k])
                        c = ord(idat_data_u[k])
                    tmp[j] = chr(
                        (ord(idat_data[j]) + predictor(a, ord(idat_data_u[j]), c)) % 256
                    )
                    k += 1
                IDAT += "".join(tmp)
        return IDAT

    def zlib_decrypt(self, data):
        # Use in IDAT decompress
        z_data = zlib.decompress(data)
        return z_data

    def load_png(self) -> bytes:
        data = read_file(self.in_file)
        self.check_format(data)
        return data

    def decompress_png(self, data, channel=3, bits=8, width=1, height=1):
        # data: array[idat1,idat2,...]
        from PIL import Image

        IDAT_data = ""
        for idat in data:
            IDAT_data += idat
        z_idat = self.zlib_decrypt(IDAT_data)
        length = len(z_idat)

        if width == 0 and height == 0:
            # bruteforce
            import shutil

            channel_dict = {1: "L", 3: "RGB", 2: "LA", 4: "RGBA"}
            PATH = "tmp/"
            if os.path.isdir(PATH) is True:
                shutil.rmtree(PATH)
            os.mkdir(PATH)
            for bits in [8, 16]:
                for channel in [4, 3, 1, 2]:
                    size_list = []
                    for i in range(1, length):
                        if length % i == 0:
                            if (i - 1) % (bits / 8 * channel) == 0:
                                size_list.append((i - 1) / (bits / 8 * channel))
                                size_list.append(length / i)
                            if (length / i - 1) % (bits / 8 * channel) == 0:
                                size_list.append(
                                    (length / i - 1) / (bits / 8 * channel)
                                )
                                size_list.append(i)
                    for i in range(0, len(size_list), 2):
                        width = size_list[i]
                        height = size_list[i + 1]
                        tmp = self.clear_filter(z_idat, width, height, channel, bits)
                        if tmp != -1:
                            img = Image.frombytes(
                                channel_dict[channel], (width, height), tmp
                            )
                            # img.show()
                            filename = PATH + "test(%dx%d)_%dbits_%dchannel.png" % (
                                width,
                                height,
                                bits,
                                channel,
                            )
                            img.save(filename)

            # show all possible image
            os.startfile(os.getcwd() + "/" + PATH)
            # final size
            size = input(
                "Input width, height, bits and channel(space to split):"
            ).split()
            # remove temporary file
            shutil.rmtree(PATH)

            width = int(size[0])
            height = int(size[1])
            bits = int(size[2])
            channel = int(size[3])
            tmp = self.clear_filter(z_idat, width, height, channel, bits)
            if tmp == -1:
                print("Wrong")
                return -1
            img = Image.frombytes(channel_dict[channel], (width, height), tmp)
            img.save("decompress.png")

        else:
            if width == 1 and height == 1:
                # load PNG config
                status = self.get_pic_info()
                if status == -1:
                    return -1
                width = self.width
                height = self.height
                channel = self.channel
                bits = self.bits
            else:
                pass
            z_idat = self.clear_filter(z_idat, width, height, channel, bits)

            mode_dict = {0: "L", 2: "RGB", 3: "P", 4: "LA", 6: "RGBA"}
            img = Image.frombytes(mode_dict[self.mode], (width, height), z_idat)
            img.show()
            img.save("zlib.png")

        return 0

    def find_ancillary(self, data):
        ancillary = [  # noqa
            "cHRM",
            "gAMA",
            "sBIT",
            "PLTE",
            "bKGD",
            "sTER",
            "hIST",
            "iCCP",
            "pHYs",
            "sPLT",
            "sRGB",
            "dSIG",
            "eXIf",
            "iTXt",
            "tEXt",
            "zTXt",
            "tIME",
            "tRNS",
            "oFFs",
            "sCAL",
            "fRAc",
            "gIFg",
            "gIFt",
            "gIFx",
        ]
        attach_txt = ["eXIf", "iTXt", "tEXt", "zTXt"]
        content = {}
        for text in attach_txt:
            pos = 0
            content[text] = []
            while pos != -1:
                pos = data.find(text.encode(), pos)
                if pos != -1:
                    length = str2num(data[pos - 4 : pos])  # noqa
                    content[text].append(data[pos + 4 : pos + 4 + length])  # noqa
                    pos += 1
        return content

    def check_png(self):
        data = self.load_png()
        if data == -1:
            return -1

        self.file = write_file(self.out_file)
        res = self.check_header(data)
        if res == -1:
            print("[Finished] PNG check complete")
            return -1
        res = self.check_ihdr(data)
        if res == -1:
            print("[Finished] PNG check complete")
            return -1

        res, idat = self.check_idat(data)
        if res == -1:
            print("[Finished] PNG check complete")
            return -1
        self.check_iend(data)
        print("[Finished] PNG check complete")

        """check complete"""

        if self.choices != "":
            choice = self.choices
        else:
            msg = termcolor(
                "Notice", "Show the repaired image? " "(y or n) [default:n] "
            )
            choice = input(msg)
        if choice == "y":
            try:
                from PIL import Image  # noqa

                self.file.close()
                img = Image.open(self.out_file)
                img.show()
            except ImportError as e:
                print(termcolor("Error", e))
                print("Try 'pip install PIL' to use it")
        return 0

    def checkcrc(self, chunk_type, chunk_data, checksum):
        # CRC-32 computed over the chunk type and chunk data, but not the length
        calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        calc_crc = struct.pack("!I", calc_crc)
        if calc_crc != checksum:
            return calc_crc
        else:
            return None

    def check_format(self, data):
        png_feature = ["PNG", "IHDR", "IDAT", "IEND"]
        status = [True for p in png_feature if p.encode() in data]
        if not status:
            print(
                termcolor("Warning", "The file may be not a PNG image."),
            )
            raise ValueError("unexpected data format")
        return 0

    def check_header(self, data):
        # Header:89 50 4E 47 0D 0A 1A 0A   %PNG....
        Header = data[:8]
        if str2hex(Header) != "89504E470D0A1A0A":
            print(termcolor("Detected", "Wrong PNG header!"))
            print(
                "File header: %s\nCorrect header: 89504E470D0A1A0A" % (str2hex(Header))
            )
            if self.choices != "":
                choice = self.choices
            else:
                msg = termcolor("Notice", "Auto fixing? (y or n) " "[default:y] ")
                choice = input(msg)
            if choice == "y" or choice == "":
                Header = bytes.fromhex("89504E470D0A1A0A")
                print("[Finished] Now header:%s" % (str2hex(Header)))
            else:
                return -1
        else:
            print("[Finished] Correct PNG header")
        self.file.write(Header)
        return 0

    def find_ihdr(self, data):
        pos = data.find("IHDR".encode())
        if pos == -1:
            return -1, -1
        idat_begin = data.find("IDAT".encode())
        if idat_begin != -1:
            IHDR = data[pos - 4 : idat_begin - 4]  # noqa
        else:
            IHDR = data[pos - 4 : pos + 21]  # noqa
        return pos, IHDR

    def check_ihdr(self, data):
        # IHDR:length=13(4 bytes)+chunk_type='IHDR'
        #   (4 bytes)+chunk_ihdr(length bytes)+crc(4 bytes)
        # chunk_ihdr=width(4 bytes)+height(4 bytes)+left(5 bytes)
        pos, IHDR = self.find_ihdr(data)
        if pos == -1:
            print(termcolor("Detected", "Lost IHDR chunk"))
            return -1
        length = struct.unpack("!I", IHDR[:4])[0]
        chunk_type = IHDR[4:8]
        chunk_ihdr = IHDR[8 : 8 + length]  # noqa

        width, height = struct.unpack("!II", chunk_ihdr[:8])
        crc = IHDR[8 + length : 12 + length]  # noqa
        # check crc
        calc_crc = self.checkcrc(chunk_type, chunk_ihdr, crc)
        if calc_crc is not None:
            print(
                termcolor(
                    "Detected",
                    "Error IHDR CRC found! (offset: %s)\nchunk crc: %s\ncorrect crc: %s"
                    % (int2hex(pos + 4 + length), str2hex(crc), str2hex(calc_crc)),
                )
            )
            if self.choices != "":
                choice = self.choices
            else:
                msg = termcolor(
                    "Notice",
                    "Try fixing it? (y or n) [default:y] ",
                )
                choice = input(msg)
            if choice == "y" or choice == "":
                if width > height:
                    # fix height
                    for h in range(height, width):
                        chunk_ihdr = (
                            IHDR[8:12]
                            + struct.pack("!I", h)
                            + IHDR[16 : 8 + length]  # noqa
                        )
                        if self.checkcrc(chunk_type, chunk_ihdr, calc_crc) is None:
                            IHDR = IHDR[:8] + chunk_ihdr + calc_crc
                            print("[Finished] Successfully fix crc")
                            break
                else:
                    # fix width
                    for w in range(width, height):
                        chunk_ihdr = (
                            struct.pack("!I", w) + IHDR[12 : 8 + length]  # noqa
                        )
                        if self.checkcrc(chunk_type, chunk_ihdr, calc_crc) is None:
                            IHDR = IHDR[:8] + chunk_ihdr + calc_crc
                            print("[Finished] Successfully fix crc")
                            break
        else:
            print(
                "[Finished] Correct IHDR CRC (offset: %s): %s"
                % (int2hex(pos + 4 + length), str2hex(crc))
            )
        self.file.write(IHDR)
        print("[Finished] IHDR chunk check complete (offset: %s)" % (int2hex(pos - 4)))

        # get image information
        self.get_pic_info(ihdr=chunk_ihdr)

    def check_idat(self, data):
        # IDAT:length(4 bytes)+chunk_type='IDAT'
        #   (4 bytes)+chunk_data(length bytes)+crc(4 bytes)
        IDAT_table = []
        idat_begin = data.find(bytes.fromhex("49444154")) - 4
        if idat_begin == -1:
            print(termcolor("Detected", "Lost all IDAT chunk!"))
            return -1, ""
        if self.i_mode == 0:
            # fast: assume both chunk length are true
            idat_size = (
                struct.unpack("!I", data[idat_begin : idat_begin + 4])[0] + 12  # noqa
            )
            for i in range(idat_begin, len(data) - 12, idat_size):
                IDAT_table.append(data[i : i + idat_size])  # noqa

            if i < len(data) - 12:  # noqa # I think noqa at-least lol
                # the last IDAT chunk
                IDAT_table.append(data[i:-12])
        elif self.i_mode == 1:
            # slow but safe
            pos_IEND = data.find("IEND".encode())
            if pos_IEND != -1:
                pos_list = [
                    g.start() for g in re.finditer("IDAT", data) if g.start() < pos_IEND
                ]
            else:
                pos_list = [g.start() for g in re.finditer("IDAT", data)]
            for i in range(len(pos_list)):
                # split into IDAT
                if i + 1 == len(pos_list):
                    # IEND
                    pos1 = pos_list[i]
                    if pos_IEND != -1:
                        IDAT_table.append(data[pos1 - 4 : pos_IEND - 4])  # noqa
                    else:
                        IDAT_table.append(data[pos1 - 4 :])  # noqa
                    break
                pos1 = pos_list[i]
                pos2 = pos_list[i + 1]
                IDAT_table.append(data[pos1 - 4 : pos2 - 4])  # noqa

        offset = idat_begin
        IDAT_data_table = []
        for IDAT in IDAT_table:
            length = struct.unpack("!I", IDAT[:4])[0]
            chunk_type = IDAT[4:8]
            chunk_data = IDAT[8:-4]
            crc = IDAT[-4:]
            # check data length
            if length != len(chunk_data):
                print(
                    termcolor(
                        "Detected",
                        "Error IDAT chunk data length! (offset: %s)"
                        % (int2hex(offset)),
                    )
                )
                print(
                    "chunk length:%s\nactual length:%s"
                    % (int2hex(length)[2:], int2hex(len(chunk_data))[2:])
                )
                if self.choices != "":
                    choice = self.choices
                else:
                    msg = termcolor("Notice", "Try fixing it? (y or n) [default:y] ")
                    choice = input(msg)
                if choice == "y" or choice == "":
                    print(
                        termcolor("Warning", "Only fix because of DOS->Unix conversion")
                    )
                    # error reason:DOS->Unix conversion
                    chunk_data = self.fix_dos2_unix(
                        chunk_type, chunk_data, crc, count=abs(length - len(chunk_data))
                    )
                    if chunk_data is None:
                        print(
                            termcolor(
                                "Failed",
                                "Fixing failed, auto discard this operation...",
                            )
                        )
                        chunk_data = IDAT[8:-4]
                    else:
                        IDAT = IDAT[:8] + chunk_data + IDAT[-4:]
                        print("[Finished] Successfully recover IDAT chunk data")  # noqa
            else:
                print(
                    "[Finished] Correct IDAT chunk data length (offset: %s length: %s)"
                    % (int2hex(offset), int2hex(length)[2:])
                )
                # check crc
                calc_crc = self.checkcrc(chunk_type, chunk_data, crc)
                if calc_crc is not None:
                    print(
                        termcolor(
                            "Detected",
                            "Error IDAT CRC found! (offset: %s)\n"
                            "chunk crc: %s\ncorrect crc: %s"
                            % (
                                int2hex(offset + 8 + length),
                                str2hex(crc),
                                str2hex(calc_crc),
                            ),
                        )
                    )
                    if self.choices != "":
                        choice = self.choices
                    else:
                        msg = termcolor(
                            "Notice", "Try fixing it? (y or n) [default:y] "
                        )
                        choice = input(msg)
                    if choice == "y" or choice == "":
                        IDAT = IDAT[:-4] + calc_crc
                        print("[Finished] Successfully fix crc")

                else:
                    print(
                        "[Finished] Correct IDAT CRC (offset: %s): %s"
                        % (int2hex(offset + 8 + length), str2hex(crc))
                    )

            # write into file
            self.file.write(IDAT)
            IDAT_data_table.append(chunk_data)
            offset += len(chunk_data) + 12
        print(
            "[Finished] IDAT chunk check complete (offset: %s)" % (int2hex(idat_begin))
        )
        return 0, IDAT_data_table

    def fix_dos2_unix(self, chunk_type, chunk_data, crc, count):
        """This attempts to replace \n with \r in the data. Dunno why yet"""
        pos = -1
        pos_list = []
        find = b"\x0A"
        while True:
            pos = chunk_data.find(find, pos + 1)
            if pos == -1:
                break
            pos_list.append(pos)
        fix = b"\x0D"
        tmp = chunk_data
        for pos_all in itertools.combinations(pos_list, count):
            i = 0
            chunk_data = tmp
            for pos in pos_all:
                chunk_data = chunk_data[: pos + i] + fix + chunk_data[pos + i :]  # noqa
                i += 1
            # check crc
            if self.checkcrc(chunk_type, chunk_data, crc) is None:
                # fix success
                return chunk_data
        return None

    def check_iend(self, data: bytes):
        # IEND:length=0(4 bytes)+chunk_type='IEND'(4 bytes)+crc=AE426082(4 bytes)
        standard_IEND = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
        pos = data.find("IEND".encode())
        if pos == -1:
            print(
                termcolor("Detected", "Lost IEND chunk! Try auto fixing..."),
            )
            IEND = standard_IEND
            print("[Finished] Now IEND chunk:%s" % (str2hex(IEND)))
        else:
            IEND = data[pos - 4 : pos + 8]  # noqa
            if IEND != standard_IEND:
                print(
                    termcolor("Detected", "Error IEND chunk! Try auto fixing..."),
                )
                IEND = standard_IEND
                print("[Finished] Now IEND chunk:%s" % (str2hex(IEND)))
            else:
                print("[Finished] Correct IEND chunk")
            if data[pos + 8 :] != b"":  # noqa
                print(
                    termcolor(
                        "Detected",
                        "Some data (length: %d) append in the end (%s)"
                        % (len(data[pos + 8 :]), data[pos + 8 : pos + 18]),  # noqa
                    )
                )
                while True:
                    msg = termcolor(
                        "Notice",
                        "Try extracting them in: <1>File"
                        " <2>Terminal <3>Quit [default:3] ",
                    )
                    choice = input(msg)
                    if choice == "1":
                        filename = input("[File] Input the file name: ")
                        file = write_file(filename)
                        file.write(data[pos + 8 :])  # noqa
                        print("[Finished] Successfully write in %s" % filename)
                        os.startfile(os.getcwd())
                    elif choice == "2":
                        print("data:", data[pos + 8 :])  # noqa
                        print("hex(data):", data[pos + 8 :].encode("hex"))  # noqa
                    elif choice == "3" or choice == "":
                        break
                    else:
                        print(
                            termcolor("Error", "Illegal choice. Try again."),
                        )

        self.file.write(IEND)
        print("[Finished] IEND chunk check complete")
        return 0


if __name__ == "__main__":

    msg = """PCRT by sherlly"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="don't show the banner information"
    )
    parser.add_argument("-y", "--yes", help="auto choose yes", action="store_true")
    parser.add_argument(
        "-v", "--verbose", help="use the safe way to recover", action="store_true"
    )
    parser.add_argument(
        "-m", "--message", help="show the image information", action="store_true"
    )
    parser.add_argument("-n", "--name", help="payload name [Default: random]")
    parser.add_argument("-p", "--payload", help="payload to hide")
    parser.add_argument(
        "-w",
        "--way",
        type=int,
        default=1,
        help="payload chunk: [1]: ancillary [2]: critical [Default:1]",
    )

    parser.add_argument("-d", "--decompress", help="decompress zlib data file name")

    parser.add_argument(
        "-i", "--input", help="Input file name (*.png) [Select from terminal]"
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Input file name (*.png) [Select from window]",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output.png",
        help="Output repaired file name [Default: output.png]",
    )
    args = parser.parse_args()

    in_file = args.input
    out_file = args.output
    payload = args.payload
    payload_name = args.name
    z_file = args.decompress

    if args.quiet is not True:
        print(msg)

    if z_file is not None:
        z_data = read_file(z_file)
        my_png = PNG()
        my_png.decompress_png(z_data, width=0, height=0)
    else:
        if args.verbose is True:
            mode = 1
        else:
            mode = 0
        if args.file is True:
            try:
                import tkinter
                import tkinter.filedialog

                root = tkinter.Tk()
                in_file = tkinter.filedialog.askopenfilename()
                root.destroy()
                # noinspection DuplicatedCode
                if args.yes is True:
                    my_png = PNG(in_file, out_file, choices="y", mode=mode)
                else:
                    my_png = PNG(in_file, out_file, mode=mode)
                if args.message is True:
                    my_png.print_pic_info()
                elif payload is not None:
                    way = args.way
                    my_png.add_payload(payload_name, payload, way)
                else:
                    my_png.check_png()
            except ImportError as e:
                print(termcolor("Error", e))
                print("Try 'pip install Tkinter' to use it")
        elif in_file is not None:
            # noinspection DuplicatedCode
            if args.yes is True:
                my_png = PNG(in_file, out_file, choices="y", mode=mode)
            else:
                my_png = PNG(in_file, out_file, mode=mode)
            if args.message is True:
                my_png.print_pic_info()
            elif payload is not None:
                way = args.way
                my_png.add_payload(payload_name, payload, way)
            else:
                my_png.check_png()
        else:
            parser.print_help()
