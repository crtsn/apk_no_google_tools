#!/bin/env python3

# Based on androguard's code https://androguard.readthedocs.io/en/latest/intro/axml.html

import re
import io
import sys
from typing import BinaryIO, Union
from struct import pack, unpack

from loguru import logger
from lxml import etree

import public
from internal_types import *

logger.remove()  # All configured handlers are removed
fmt = "{message}"
fmt = "{line: >4}:{level}:\t{message}"
logger.add(sys.stderr, format=fmt)

# Constants for ARSC Files
# see http://aospxref.com/android-13.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#233
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

RES_XML_FIRST_CHUNK_TYPE = 0x0100
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_LAST_CHUNK_TYPE = 0x017F

RES_XML_RESOURCE_MAP_TYPE = 0x0180

RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203
RES_TABLE_OVERLAYABLE_TYPE = 0x0204
RES_TABLE_OVERLAYABLE_POLICY_TYPE = 0x0205
RES_TABLE_STAGED_ALIAS_TYPE = 0x0206
# Flags in the STRING Section
SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8

# Position of the fields inside an attribute
ATTRIBUTE_IX_NAMESPACE_URI = 0
ATTRIBUTE_IX_NAME = 1
ATTRIBUTE_IX_VALUE_STRING = 2
ATTRIBUTE_IX_VALUE_TYPE = 3
ATTRIBUTE_IX_VALUE_DATA = 4
ATTRIBUTE_LENGTH = 5

# Internally used state variables for AXMLParser
START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4

# Table used to lookup functions to determine the value representation in ARSCParser
TYPE_TABLE = {
    TYPE_ATTRIBUTE: "attribute",
    TYPE_DIMENSION: "dimension",
    TYPE_FLOAT: "float",
    TYPE_FRACTION: "fraction",
    TYPE_INT_BOOLEAN: "int_boolean",
    TYPE_INT_COLOR_ARGB4: "int_color_argb4",
    TYPE_INT_COLOR_ARGB8: "int_color_argb8",
    TYPE_INT_COLOR_RGB4: "int_color_rgb4",
    TYPE_INT_COLOR_RGB8: "int_color_rgb8",
    TYPE_INT_DEC: "int_dec",
    TYPE_INT_HEX: "int_hex",
    TYPE_NULL: "null",
    TYPE_REFERENCE: "reference",
    TYPE_STRING: "string",
}

RADIX_MULTS = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]

COMPLEX_UNIT_MASK = 0x0F

class ResParserError(Exception):
    """Exception for the parsers"""

    pass

class ARSCHeader:
    """
    Object which contains a Resource Chunk.
    This is an implementation of the `ResChunk_header`.

    It will throw an [ResParserError][androguard.core.axml.ResParserError] if the header could not be read successfully.

    It is not checked if the data is outside the buffer size nor if the current
    chunk fits into the parent chunk (if any)!

    The parameter `expected_type` can be used to immediately check the header for the type or raise a [ResParserError][androguard.core.axml.ResParserError].
    This is useful if you know what type of chunk must follow.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#196
    """

    # This is the minimal size such a header must have. There might be other header data too!
    SIZE = 2 + 2 + 4

    def __init__(
        self,
        buff: BinaryIO,
        expected_type: Union[int, None] = None
    ) -> None:
        """
        :raises ResParserError: if header malformed
        :param buff: the buffer set to the position where the header starts.
        :param int expected_type: the type of the header which is expected.
        """
        self.start = buff.tell()
        # Make sure we do not read over the buffer:
        if buff.raw.getbuffer().nbytes < self.start + self.SIZE:
            raise ResParserError(
                "Can not read over the buffer size! Offset={}".format(
                    self.start
                )
            )

        # Checking for dummy data between elements
        while True:
            cur_pos = buff.tell()
            self._type, self._header_size, self._size = unpack(
                '<HHL', buff.read(self.SIZE)
            )
            logger.debug(f"ARSCHeader init: {self._type}, {self._header_size} {self._size}")

            # cases where packers set the EndNamespace with zero size: check we are the end and add the prefix + uri
            if self._size < self.SIZE and (
                buff.raw.getbuffer().nbytes
                == cur_pos + self._header_size + 4 + 4
            ):
                self._size = 24
            header_ok = self._header_size >= self.SIZE and self._size >= self._header_size
            if (self._type < RES_XML_FIRST_CHUNK_TYPE or self._type > RES_XML_LAST_CHUNK_TYPE) and header_ok:
                break
            if cur_pos == 0 or header_ok:
                break
            buff.seek(cur_pos)
            buff.read(1)
            logger.warning(
                "Appears that dummy data are found between elements!"
            )

        if expected_type and self._type != expected_type:
            raise ResParserError(
                "Header type is not equal the expected type: Got 0x{:04x}, wanted 0x{:04x}".format(
                    self._type, expected_type
                )
            )

        # Assert that the read data will fit into the chunk.
        # The total size must be equal or larger than the header size
        if self._header_size < self.SIZE:
            raise ResParserError(
                "declared header size is smaller than required size of {}! Offset={}".format(
                    self.SIZE, self.start
                )
            )
        if self._size < self.SIZE:
            raise ResParserError(
                "declared chunk size is smaller than required size of {}! Offset={}".format(
                    self.SIZE, self.start
                )
            )
        if self._size < self._header_size:
            raise ResParserError(
                "declared chunk size ({}) is smaller than header size ({})! Offset={}".format(
                    self._size, self._header_size, self.start
                )
            )

    def get_type(self) -> int:
        """
        Type identifier for this chunk
        """
        return self._type

    def get_header_size(self) -> int:
        """
        Size of the chunk header (in bytes).  Adding this value to
        the address of the chunk allows you to find its associated data
        (if any).
        """
        return self._header_size

    def get_size(self) -> int:
        """
        Total size of this chunk (in bytes).  This is the chunkSize plus
        the size of any data associated with the chunk.  Adding this value
        to the chunk allows you to completely skip its contents (including
        any child chunks).  If this value is the same as chunkSize, there is
        no data associated with the chunk.
        """
        return self._size

    def get_end(self) -> int:
        """
        Get the absolute offset inside the file, where the chunk ends.
        This is equal to `ARSCHeader.start + ARSCHeader.get_size()`.
        """
        return self.start + self.get_size()

    def __repr__(self):
        return "<ARSCHeader idx='0x{:08x}' type='{}' header_size='{}' size='{}'>".format(
            self.start, self.get_type(), self.get_header_size(), self.get_size()
        )

class StringBlock:
    """
    StringBlock is a CHUNK inside an AXML File: `ResStringPool_header`
    It contains all strings, which are used by referencing to ID's

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#436
    """

    def __init__(self, buff: BinaryIO, header: ARSCHeader) -> None:
        """
        :param buff: buffer which holds the string block
        :param header: a instance of [ARSCHeader][androguard.core.axml.ARSCHeader]
        """
        self._cache = {}
        self.header = header
        # We already read the header (which was chunk_type and chunk_size
        # Now, we read the string_count:
        self.stringCount = unpack('<I', buff.read(4))[0]
        # style_count
        self.styleCount = unpack('<I', buff.read(4))[0]

        logger.debug(f"stringCount: {self.stringCount}")
        logger.debug(f"styleCount: {self.styleCount}")


        # flags
        self.flags = unpack('<I', buff.read(4))[0]
        self.m_isUTF8 = (self.flags & UTF8_FLAG) != 0
        logger.debug(f"flags: {self.flags}")
        logger.debug(f"m_isUTF8: {self.m_isUTF8}")

        # string_pool_offset
        # The string offset is counted from the beginning of the string section
        self.stringsOffset = unpack('<I', buff.read(4))[0]
        # check if the stringCount is correct
        if (
            self.stringsOffset - (self.styleCount * 4 + 28)
        ) / 4 != self.stringCount:
            self.stringCount = int(
                (self.stringsOffset - (self.styleCount * 4 + 28)) / 4
            )
        logger.debug(f"stringsOffset: {self.stringsOffset}")
        logger.debug(f"stringCount: {self.stringCount}")

        # style_pool_offset
        # The styles offset is counted as well from the beginning of the string section
        self.stylesOffset = unpack('<I', buff.read(4))[0]

        # Check if they supplied a stylesOffset even if the count is 0:
        if self.styleCount == 0 and self.stylesOffset > 0:
            logger.info(
                "Styles Offset given, but styleCount is zero. "
                "This is not a problem but could indicate packers."
            )

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_charbuff = ""
        self.m_styles = []
        logger.debug(f"stylesOffset: {self.stylesOffset}")
        logger.debug(f"styleCount: {self.styleCount}")

        # Next, there is a list of string following.
        # This is only a list of offsets (4 byte each)
        for i in range(self.stringCount):
            self.m_stringOffsets.append(unpack('<I', buff.read(4))[0])
            logger.debug(f"m_stringOffsets[{i}]: {self.m_stringOffsets[i]}")
        # And a list of styles
        # again, a list of offsets
        for i in range(self.styleCount):
            self.m_styleOffsets.append(unpack('<I', buff.read(4))[0])
            logger.debug(f"m_styleOffsets[{i}]: {self.m_styleOffsets[i]}")

        # FIXME it is probably better to parse n strings and not calculate the size
        size = self.header.get_size() - self.stringsOffset

        # if there are styles as well, we do not want to read them too.
        # Only read them, if no
        if self.stylesOffset != 0 and self.styleCount != 0:
            size = self.stylesOffset - self.stringsOffset

        if (size % 4) != 0:
            logger.warning("Size of strings is not aligned by four bytes.")

        self.m_charbuff = buff.read(size)
        for i in range(self.stringCount):
            self.getString(i)


        if self.stylesOffset != 0 and self.styleCount != 0:
            size = self.header.get_size() - self.stylesOffset

            if (size % 4) != 0:
                logger.warning("Size of styles is not aligned by four bytes.")

            for i in range(0, size // 4):
                self.m_styles.append(unpack('<I', buff.read(4))[0])

    def __repr__(self):
        return "<StringPool #strings={}, #styles={}, UTF8={}>".format(
            self.stringCount, self.styleCount, self.m_isUTF8
        )

    def __getitem__(self, idx):
        """
        Returns the string at the index in the string table

        :returns: the string
        """
        return self.getString(idx)

    def __len__(self):
        """
        Get the number of strings stored in this table

        :return: the number of strings
        """
        return self.stringCount

    def __iter__(self):
        """
        Iterable over all strings

        :returns: a generator over all strings
        """
        for i in range(self.stringCount):
            yield self.getString(i)

    def getString(self, idx: int) -> str:
        """
        Return the string at the index in the string table

        :param idx: index in the string table
        :return: the string
        """
        if idx in self._cache:
            logger.debug(f"getString: {idx}: FROM CACHE: {self._cache[idx]}")
            return self._cache[idx]

        if idx < 0 or not self.m_stringOffsets or idx >= self.stringCount:
            return ""

        offset = self.m_stringOffsets[idx]

        if self.m_isUTF8:
            self._cache[idx] = self._decode8(offset)
        else:
            self._cache[idx] = self._decode16(offset)
        logger.debug(f"getString: {idx}: CACHED: {self._cache[idx]}")

        return self._cache[idx]

    def getStyle(self, idx: int) -> int:
        """
        Return the style associated with the index

        :param idx: index of the style
        :return: the style integer
        """
        return self.m_styles[idx]

    def _decode8(self, offset: int) -> str:
        """
        Decode an UTF-8 String at the given offset

        :param offset: offset of the string inside the data
        :raises ResParserError: if string is not null terminated
        :return: the decoded string
        """
        # UTF-8 Strings contain two lengths, as they might differ:
        # 1) the UTF-16 length
        str_len, skip = self._decode_length(offset, 1)
        offset += skip

        # 2) the utf-8 string length
        encoded_bytes, skip = self._decode_length(offset, 1)
        offset += skip

        # Two checks should happen here:
        # a) offset + encoded_bytes surpassing the string_pool length and
        # b) non-null terminated strings which should be rejected
        # platform/frameworks/base/libs/androidfw/ResourceTypes.cpp#789
        if len(self.m_charbuff) < (offset + encoded_bytes):
            logger.warning(
                f"String size: {offset + encoded_bytes} is exceeding string pool size. Returning empty string."
            )
            return ""
        data = self.m_charbuff[offset : offset + encoded_bytes]

        if self.m_charbuff[offset + encoded_bytes] != 0:
            logger.warning(
                "UTF-8 String is not null terminated! At offset={}".format(offset)
            )
            return ""

        return self._decode_bytes(data, 'utf-8', str_len)

    def _decode16(self, offset: int) -> str:
        """
        Decode an UTF-16 String at the given offset

        :param offset: offset of the string inside the data
        :raises ResParserError: if string is not null terminated

        :return: the decoded string
        """
        str_len, skip = self._decode_length(offset, 2)
        offset += skip

        # The len is the string len in utf-16 units
        encoded_bytes = str_len * 2

        # Two checks should happen here:
        # a) offset + encoded_bytes surpassing the string_pool length and
        # b) non-null terminated strings which should be rejected
        # platform/frameworks/base/libs/androidfw/ResourceTypes.cpp#789
        if len(self.m_charbuff) < (offset + encoded_bytes):
            logger.warning(
                f"String size: {offset + encoded_bytes} is exceeding string pool size. Returning empty string."
            )
            return ""

        data = self.m_charbuff[offset : offset + encoded_bytes]

        if (
            self.m_charbuff[
                offset + encoded_bytes : offset + encoded_bytes + 2
            ]
            != b"\x00\x00"
        ):
            raise ResParserError(
                "UTF-16 String is not null terminated! At offset={}".format(
                    offset
                )
            )

        return self._decode_bytes(data, 'utf-16', str_len)

    @staticmethod
    def _decode_bytes(data: bytes, encoding: str, str_len: int) -> str:
        """
        Generic decoding with length check.
        The string is decoded from bytes with the given encoding, then the length
        of the string is checked.
        The string is decoded using the "replace" method.

        :param data: bytes
        :param encoding: encoding name ("utf-8" or "utf-16")
        :param str_len: length of the decoded string
        :return: the decoded bytes
        """
        string = data.decode(encoding, 'replace')
        if len(string) != str_len:
            logger.warning("invalid decoded string length")
        return string

    def _decode_length(self, offset: int, sizeof_char: int) -> tuple[int, int]:
        """
        Generic Length Decoding at offset of string

        The method works for both 8 and 16 bit Strings.
        Length checks are enforced:
        * 8 bit strings: maximum of 0x7FFF bytes (See
        http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#692)
        * 16 bit strings: maximum of 0x7FFFFFF bytes (See
        http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#670)

        :param offset: offset into the string data section of the beginning of
        the string
        :param sizeof_char: number of bytes per char (1 = 8bit, 2 = 16bit)
        :returns: tuple of (length, read bytes)
        """
        sizeof_2chars = sizeof_char << 1
        fmt = "<2{}".format('B' if sizeof_char == 1 else 'H')
        highbit = 0x80 << (8 * (sizeof_char - 1))

        length1, length2 = unpack(
            fmt, self.m_charbuff[offset : (offset + sizeof_2chars)]
        )

        if (length1 & highbit) != 0:
            length = ((length1 & ~highbit) << (8 * sizeof_char)) | length2
            size = sizeof_2chars
        else:
            length = length1
            size = sizeof_char

        # These are true asserts, as the size should never be less than the values
        if sizeof_char == 1:
            assert (
                length <= 0x7FFF
            ), "length of UTF-8 string is too large! At offset={}".format(
                offset
            )
        else:
            assert (
                length <= 0x7FFFFFFF
            ), "length of UTF-16 string is too large!  At offset={}".format(
                offset
            )

        return length, size

    def show(self) -> None:
        """
        Print some information on stdout about the string table
        """
        print(
            "StringBlock(stringsCount=0x%x, "
            "stringsOffset=0x%x, "
            "stylesCount=0x%x, "
            "stylesOffset=0x%x, "
            "flags=0x%x"
            ")"
            % (
                self.stringCount,
                self.stringsOffset,
                self.styleCount,
                self.stylesOffset,
                self.flags,
            )
        )

        if self.stringCount > 0:
            print()
            print("String Table: ")
            for i, s in enumerate(self):
                print("{:08d} {}".format(i, repr(s)))

        if self.styleCount > 0:
            print()
            print("Styles Table: ")
            for i in range(self.styleCount):
                print("{:08d} {}".format(i, repr(self.getStyle(i))))

class AXMLParser:
    """
    `AXMLParser` reads through all chunks in the AXML file
    and implements a state machine to return information about
    the current chunk, which can then be read by [AXMLPrinter][androguard.core.axml.AXMLPrinter].

    An AXML file is a file which contains multiple chunks of data, defined
    by the `ResChunk_header`.
    There is no real file magic but as the size of the first header is fixed
    and the `type` of the `ResChunk_header` is set to `RES_XML_TYPE`, a file
    will usually start with `0x03000800`.
    But there are several examples where the `type` is set to something
    else, probably in order to fool parsers.

    Typically the `AXMLParser` is used in a loop which terminates if `m_event` is set to `END_DOCUMENT`.
    You can use the `next()` function to get the next chunk.
    Note that not all chunk types are yielded from the iterator! Some chunks are processed in
    the `AXMLParser` only.
    The parser will set [is_valid][androguard.core.axml.AXMLParser.is_valid] to `False` if it parses something not valid.
    Messages what is wrong are logged.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#563
    """

    def __init__(self, raw_buff: bytes) -> None:
        logger.debug("AXMLParser")

        self._reset()

        self._valid = True
        self.axml_tampered = False
        self.buff = io.BufferedReader(io.BytesIO(raw_buff))
        self.buff_size = self.buff.raw.getbuffer().nbytes
        self.packerwarning = False

        # Minimum is a single ARSCHeader, which would be a strange edge case...
        logger.debug(f"buff_size: {self.buff_size}")
        if self.buff_size < 8:
            logger.error(
                "Filesize is too small to be a valid AXML file! Filesize: {}".format(
                    self.buff_size
                )
            )
            self._valid = False
            return

        # This would be even stranger, if an AXML file is larger than 4GB...
        # But this is not possible as the maximum chunk size is a unsigned 4 byte int.
        if self.buff_size > 0xFFFFFFFF:
            logger.error(
                "Filesize is too large to be a valid AXML file! Filesize: {}".format(
                    self.buff_size
                )
            )
            self._valid = False
            return

        try:
            axml_header = ARSCHeader(self.buff)
            logger.debug("FIRST HEADER {}".format(axml_header))
        except ResParserError as e:
            logger.error("Error parsing first resource header: %s", e)
            self._valid = False
            return

        self.filesize = axml_header.get_size()

        if axml_header.get_header_size() == 28024:
            # Can be a common error: the file is not an AXML but a plain XML
            # The file will then usually start with '<?xm' / '3C 3F 78 6D'
            logger.warning(
                "Header size is 28024! Are you trying to parse a plain XML file?"
            )

        if axml_header.get_header_size() != 8:
            logger.error(
                "This does not look like an AXML file. header size does not equal 8! header size = {}".format(
                    axml_header.get_header_size()
                )
            )
            self._valid = False
            return

        if self.filesize > self.buff_size:
            logger.error(
                "This does not look like an AXML file. Declared filesize does not match real size: {} vs {}".format(
                    self.filesize, self.buff_size
                )
            )
            self._valid = False
            return

        if self.filesize < self.buff_size:
            # The file can still be parsed up to the point where the chunk should end.
            self.axml_tampered = True
            logger.warning(
                "Declared filesize ({}) is smaller than total file size ({}). "
                "Was something appended to the file? Trying to parse it anyways.".format(
                    self.filesize, self.buff_size
                )
            )

        # Not that severe of an error, we have plenty files where this is not
        # set correctly
        if axml_header.get_type() != RES_XML_TYPE:
            self.axml_tampered = True
            logger.warning(
                "AXML file has an unusual resource type! "
                "Malware likes to to such stuff to anti androguard! "
                "But we try to parse it anyways. Resource Type: 0x{:04x}".format(
                    axml_header.get_type()
                )
            )

        # Now we parse the STRING POOL
        try:
            header = ARSCHeader(self.buff, expected_type=RES_STRING_POOL_TYPE)
            logger.debug("STRING_POOL {}".format(header))
        except ResParserError as e:
            logger.error(
                "Error parsing resource header of string pool: {}".format(e)
            )
            self._valid = False
            return

        if header.get_header_size() != 0x1C:
            logger.error(
                "This does not look like an AXML file. String chunk header size does not equal 28! header size = {}".format(
                    header.get_header_size()
                )
            )
            self._valid = False
            return

        self.sb = StringBlock(self.buff, header)

        self.buff.seek(axml_header.get_header_size() + header.get_size())

        # Stores resource ID mappings, if any
        self.m_resourceIDs = []

        # Store a list of prefix/uri mappings encountered
        self.namespaces = []

    def is_valid(self) -> bool:
        """
        Get the state of the [AXMLPrinter][androguard.core.axml.AXMLPrinter].
        if an error happend somewhere in the process of parsing the file,
        this flag is set to `False`.

        :returns: `True` if the `AXMLPrinter` finished parsing, or `False` if an error occurred
        """
        logger.debug(self._valid)
        return self._valid

    def _reset(self):
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def __next__(self):
        event_name = "WRONG"
        if self.m_event == START_DOCUMENT:
            event_name = "START_DOCUMENT"
        elif self.m_event == END_DOCUMENT:
            event_name = "END_DOCUMENT"
        elif self.m_event == START_TAG:
            event_name = "START_TAG"
        elif self.m_event == END_TAG:
            event_name = "END_TAG"
        elif self.m_event == TEXT:
            event_name = "TEXT"

        logger.debug(f"M_EVENT {self.m_event}: {event_name}")

        if self.m_event == END_DOCUMENT:
            return self.m_event

        self._reset()
        while self._valid:
            # Stop at the declared filesize or at the end of the file
            if self.buff.tell() == self.filesize:
                self.m_event = END_DOCUMENT
                break

            # Again, we read an ARSCHeader
            try:
                h = ARSCHeader(self.buff)
                logger.debug("NEXT HEADER {}".format(h))
            except ResParserError as e:
                logger.error("Error parsing resource header: {}".format(e))
                self._valid = False
                return self.m_event
            if h.get_type() == RES_XML_RESOURCE_MAP_TYPE:
                type_name = "RES_XML_RESOURCE_MAP_TYPE"
            if h.get_type() == RES_XML_FIRST_CHUNK_TYPE:
                type_name = "RES_XML_FIRST_CHUNK_TYPE"
            if h.get_type() == RES_XML_START_NAMESPACE_TYPE:
                type_name = "RES_XML_START_NAMESPACE_TYPE"
            if h.get_type() == RES_XML_END_NAMESPACE_TYPE:
                type_name = "RES_XML_END_NAMESPACE_TYPE"
            if h.get_type() == RES_XML_START_ELEMENT_TYPE:
                type_name = "RES_XML_START_ELEMENT_TYPE"
            if h.get_type() == RES_XML_END_ELEMENT_TYPE:
                type_name = "RES_XML_END_ELEMENT_TYPE"
            if h.get_type() == RES_XML_CDATA_TYPE:
                type_name = "RES_XML_CDATA_TYPE"
            if h.get_type() == RES_XML_LAST_CHUNK_TYPE:
                type_name = "RES_XML_LAST_CHUNK_TYPE"

            logger.debug(f"__next__: {type_name}")
            # Special chunk: Resource Map. This chunk might be contained inside
            # the file, after the string pool.
            if h.get_type() == RES_XML_RESOURCE_MAP_TYPE:
                logger.debug("AXML contains a RESOURCE MAP")
                # Check size: < 8 bytes mean that the chunk is not complete
                # Should be aligned to 4 bytes.
                if h.get_size() < 8 or (h.get_size() % 4) != 0:
                    logger.error(
                        "Invalid chunk size in chunk XML_RESOURCE_MAP"
                    )
                    self._valid = False
                    return self.m_event

                for i in range((h.get_size() - h.get_header_size()) // 4):
                    self.m_resourceIDs.append(
                        unpack('<L', self.buff.read(4))[0]
                    )
                    logger.debug(f"m_resourceIDs[{i}]: {self.m_resourceIDs[i]}")

                continue

            # Parse now the XML chunks.
            # unknown chunk types might cause problems, but we can skip them!
            if (
                h.get_type() < RES_XML_FIRST_CHUNK_TYPE
                or h.get_type() > RES_XML_LAST_CHUNK_TYPE
            ):
                # h.get_size() is the size of the whole chunk including the header.
                # We read already 8 bytes of the header, thus we need to
                # subtract them.
                logger.error(
                    "Not a XML resource chunk type: 0x{:04x}. Skipping {} bytes".format(
                        h.get_type(), h.get_size()
                    )
                )
                self.buff.seek(h.get_end())
                continue

            # Check that we read a correct header
            if h.get_header_size() != 0x10:
                logger.error(
                    "XML Resource Type Chunk header size does not match 16! "
                    "At chunk type 0x{:04x}, declared header size=0x{:04x}, chunk size=0x{:04x}".format(
                        h.get_type(), h.get_header_size(), h.get_size()
                    )
                )
                self.buff.seek(h.get_end())
                continue

            # Line Number of the source file, only used as meta information
            (self.m_lineNumber,) = unpack('<L', self.buff.read(4))
            logger.debug(f"m_lineNumber: {self.m_lineNumber}")

            # Comment_Index (usually 0xFFFFFFFF)
            (self.m_comment_index,) = unpack('<L', self.buff.read(4))
            logger.debug(f"m_comment_index: {self.m_comment_index}")

            if self.m_comment_index != 0xFFFFFFFF and h.get_type() in [
                RES_XML_START_NAMESPACE_TYPE,
                RES_XML_END_NAMESPACE_TYPE,
            ]:
                logger.error(
                    "Unhandled Comment at namespace chunk: '{}'".format(
                        self.sb[self.m_comment_index]
                    )
                )

            if h.get_type() == RES_XML_START_NAMESPACE_TYPE:
                (prefix,) = unpack('<L', self.buff.read(4))
                logger.debug(f"prefix: {prefix}")
                (uri,) = unpack('<L', self.buff.read(4))
                logger.debug(f"uri: {uri}")

                s_prefix = self.sb[prefix]
                s_uri = self.sb[uri]

                logger.debug(
                    "Start of Namespace mapping: prefix {}: '{}' --> uri {}: '{}'".format(
                        prefix, s_prefix, uri, s_uri
                    )
                )

                if s_uri == '':
                    logger.error(
                        "Namespace prefix '{}' resolves to empty URI. "
                        "This might be a packer.".format(s_prefix)
                    )

                if (prefix, uri) in self.namespaces:
                    logger.debug(
                        "Namespace mapping ({}, {}) already seen! "
                        "This is usually not a problem but could indicate packers or broken AXML compilers.".format(
                            prefix, uri
                        )
                    )
                self.namespaces.append((prefix, uri))

                # We can continue with the next chunk, as we store the namespace
                # mappings for each tag
                continue

            if h.get_type() == RES_XML_END_NAMESPACE_TYPE:
                # END_PREFIX contains again prefix and uri field
                (prefix,) = unpack('<L', self.buff.read(4))
                logger.debug(f"prefix: {prefix}")
                (uri,) = unpack('<L', self.buff.read(4))
                logger.debug(f"uri: {uri}")

                # We remove the last namespace mapping matching
                if (prefix, uri) in self.namespaces:
                    self.namespaces.remove((prefix, uri))
                else:
                    logger.warning(
                        "Reached a NAMESPACE_END without having the namespace stored before? "
                        "Prefix ID: {}, URI ID: {}".format(prefix, uri)
                    )

                # We can continue with the next chunk, as we store the namespace
                # mappings for each tag
                continue

            # START_TAG is the start of a new tag.
            if h.get_type() == RES_XML_START_ELEMENT_TYPE:
                # The TAG consists of some fields:
                # * (chunk_size, line_number, comment_index - we read before)
                # * namespace_uri
                # * name
                # * flags
                # * attribute_count
                # * class_attribute
                # After that, there are two lists of attributes, 20 bytes each

                # Namespace URI (String ID)
                (self.m_namespaceUri,) = unpack('<L', self.buff.read(4))
                logger.debug(f"m_namespaceUri: {self.m_namespaceUri}")
                # Name of the Tag (String ID)
                (self.m_name,) = unpack('<L', self.buff.read(4))
                logger.debug(f"m_name: {self.m_name}")
                self.at_start, self.at_size = unpack('<HH', self.buff.read(4))
                logger.debug(f"at_start: {self.at_start}")
                logger.debug(f"at_size: {self.at_size}")
                # Attribute Count
                (attributeCount,) = unpack('<L', self.buff.read(4))
                logger.debug(f"attributeCount: {attributeCount}")
                # Class Attribute
                (self.m_classAttribute,) = unpack('<L', self.buff.read(4))
                logger.debug(f"m_classAttribute: {self.m_classAttribute}")

                self.m_idAttribute = (attributeCount >> 16) - 1
                self.m_attribute_count = attributeCount & 0xFFFF
                self.m_styleAttribute = (self.m_classAttribute >> 16) - 1
                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                # Now, we parse the attributes.
                # Each attribute has 5 fields of 4 byte
                for i in range(0, self.m_attribute_count):
                    # Each field is linearly parsed into the array
                    # Each Attribute contains:
                    # * Namespace URI (String ID)
                    # * Name (String ID)
                    # * Value
                    # * Type
                    # * Data
                    for j in range(0, ATTRIBUTE_LENGTH):
                        self.m_attributes.append(
                            unpack('<L', self.buff.read(4))[0]
                        )
                        logger.debug(f"m_attributes[{ATTRIBUTE_LENGTH * i} + {j}]: {self.m_attributes[j]}")
                    if self.at_size != 20:
                        self.buff.read(self.at_size - 20)

                # Then there are class_attributes
                for i in range(
                    ATTRIBUTE_IX_VALUE_TYPE,
                    len(self.m_attributes),
                    ATTRIBUTE_LENGTH,
                ):
                    self.m_attributes[i] = self.m_attributes[i] >> 24

                self.m_event = START_TAG
                break

            if h.get_type() == RES_XML_END_ELEMENT_TYPE:
                (self.m_namespaceUri,) = unpack('<L', self.buff.read(4))
                (self.m_name,) = unpack('<L', self.buff.read(4))

                self.m_event = END_TAG
                break

            if h.get_type() == RES_XML_CDATA_TYPE:
                # The CDATA field is like an attribute.
                # It contains an index into the String pool
                # as well as a typed value.
                # usually, this typed value is set to UNDEFINED

                # ResStringPool_ref data --> uint32_t index
                (self.m_name,) = unpack('<L', self.buff.read(4))

                # Res_value typedData:
                # uint16_t size
                # uint8_t res0 -> always zero
                # uint8_t dataType
                # uint32_t data
                # For now, we ingore these values
                size, res0, dataType, data = unpack("<HBBL", self.buff.read(8))

                logger.debug(
                    "found a CDATA Chunk: "
                    "index={: 6d}, size={: 4d}, res0={: 4d}, dataType={: 4d}, data={: 4d}".format(
                        self.m_name, size, res0, dataType, data
                    )
                )

                self.m_event = TEXT
                break

            # Still here? Looks like we read an unknown XML header, try to skip it...
            logger.warning(
                "Unknown XML Chunk: 0x{:04x}, skipping {} bytes.".format(
                    h.get_type(), h.get_size()
                )
            )
            self.buff.seek(h.get_end())
        # added to cover the case where reading the element chunk was not adequate to read
        # the same amount of bytes as instructed by the header
        if 'h' in locals():
            if self.buff.tell() != h.get_end():
                self.buff.seek(h.get_end())
        return self.m_event

    def get_name(self) -> str:
        """
        Return the String associated with the tag name

        :returns: the string
        """
        if self.m_name == -1 or (
            self.m_event != START_TAG and self.m_event != END_TAG
        ):
            return ''

        logger.debug(f"self.m_name: {self.m_name}")
        return self.sb[self.m_name]

    def get_comment(self) -> Union[str, None]:
        """
        Return the comment at the current position or None if no comment is given

        This works only for Tags, as the comments of Namespaces are silently dropped.
        Currently, there is no way of retrieving comments of namespaces.

        :returns: the comment string, or None if no comment exists
        """
        if self.m_comment_index == 0xFFFFFFFF:
            return None

        return self.sb[self.m_comment_index]

    def get_namespace(self) -> str:
        """
        Return the Namespace URI (if any) as a String for the current tag

        :returns: the namespace uri, or empty if namespace does not exist
        """
        if self.m_name == -1 or (
            self.m_event != START_TAG and self.m_event != END_TAG
        ):
            return ''

        # No Namespace
        if self.m_namespaceUri == 0xFFFFFFFF:
            return ''

        return self.sb[self.m_namespaceUri]

    def get_nsmap(self) -> dict[str, str]:
        """
        Returns the current namespace mapping as a dictionary

        there are several problems with the map and we try to guess a few
        things here:

        1) a URI can be mapped by many prefixes, so it is to decide which one to take
        2) a prefix might map to an empty string (some packers)
        3) uri+prefix mappings might be included several times
        4) prefix might be empty

        :returns: the namespace mapping dictionary
        """

        NSMAP = dict()
        # solve 3) by using a set
        for k, v in set(self.namespaces):
            s_prefix = self.sb[k]
            s_uri = self.sb[v]
            # Solve 2) & 4) by not including
            if s_uri != "" and s_prefix != "":
                # solve 1) by using the last one in the list
                NSMAP[s_prefix] = s_uri.strip()

        return NSMAP

    def get_text(self) -> str:
        """
        Return the String assosicated with the current text

        :returns: the string associated with the current text
        """
        if self.m_name == -1 or self.m_event != TEXT:
            return ''

        return self.sb[self.m_name]

    def _get_attribute_offset(self, index: int):
        """
        Return the start inside the m_attributes array for a given attribute
        """
        if self.m_event != START_TAG:
            logger.warning("Current event is not START_TAG.")

        offset = index * ATTRIBUTE_LENGTH
        if offset >= len(self.m_attributes):
            logger.warning("Invalid attribute index")

        return offset

    def getAttributeCount(self) -> int:
        """
        Return the number of Attributes for a Tag
        or -1 if not in a tag

        :returns: the number of attributes
        """
        if self.m_event != START_TAG:
            return -1

        return self.m_attribute_count

    def getAttributeUri(self, index:int) -> int:
        """
        Returns the numeric ID for the namespace URI of an attribute

        :returns: the namespace URI numeric id
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        uri = self.m_attributes[offset + ATTRIBUTE_IX_NAMESPACE_URI]

        return uri

    def getAttributeNamespace(self, index:int) -> str:
        """
        Return the Namespace URI (if any) for the attribute

        :returns: the attribute uri, or empty string if no namespace
        """
        logger.debug(index)

        uri = self.getAttributeUri(index)

        # No Namespace
        if uri == 0xFFFFFFFF:
            return ''

        return self.sb[uri]

    def getAttributeName(self, index:int) -> str:
        """
        Returns the String which represents the attribute name

        :returns: the attribute name
        """
        logger.debug(index)
        offset = self._get_attribute_offset(index)
        name = self.m_attributes[offset + ATTRIBUTE_IX_NAME]
        attr = None
        res = self.sb[name]
        # If the result is a (null) string, we need to look it up.
        logger.debug(f"getAttributeName: name: {name}")
        if name < len(self.m_resourceIDs):
            attr = self.m_resourceIDs[name]
            if attr in public.SYSTEM_RESOURCES['attributes']['inverse']:
                res = public.SYSTEM_RESOURCES['attributes']['inverse'][
                    attr
                ].replace("_", ":")
                if res != self.sb[name]:
                    self.packerwarning = True

        if not res or res == ":":
            # Attach the HEX Number, so for multiple missing attributes we do not run
            # into problems.
            if attr:
                res = 'android:UNKNOWN_SYSTEM_ATTRIBUTE_{:08x}'.format(attr)
            else:
                res = 'android:UNKNOWN_SYSTEM_ATTRIBUTE_{:08x}'.format(random.randint(1, 1137))
        logger.debug(f"getAttributeName: {res}")
        return res

    def getAttributeValueType(self, index: int):
        """
        Return the type of the attribute at the given index

        :param index: index of the attribute
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]

    def getAttributeValueData(self, index: int):
        """
        Return the data of the attribute at the given index

        :param index: index of the attribute
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_DATA]

    def getAttributeValue(self, index: int) -> str:
        """
        This function is only used to look up strings
        All other work is done by
        [format_value][androguard.core.axml.format_value]
        # FIXME should unite those functions
        :param index: index of the attribute
        :returns: the string
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        valueType = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]
        if valueType == TYPE_STRING:
            valueString = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_STRING]
            return self.sb[valueString]
        return ''


def format_value(
    _type: int, _data: int, lookup_string=lambda ix: "<string>"
) -> str:
    """
    Format a value based on type and data.
    By default, no strings are looked up and `"<string>"` is returned.
    You need to define `lookup_string` in order to actually lookup strings from
    the string table.

    :param _type: The numeric type of the value
    :param _data: The numeric data of the value
    :param lookup_string: A function how to resolve strings from integer IDs
    :returns: the formatted string
    """

    # Function to prepend android prefix for attributes/references from the
    # android library
    fmt_package = lambda x: "android:" if x >> 24 == 1 else ""

    # Function to represent integers
    fmt_int = lambda x: (0x7FFFFFFF & x) - 0x80000000 if x > 0x7FFFFFFF else x
    if _type == TYPE_NULL:
        type_name = "TYPE_NULL"
    elif _type == TYPE_REFERENCE:
        type_name = "TYPE_REFERENCE"
    elif _type == TYPE_ATTRIBUTE:
        type_name = "TYPE_ATTRIBUTE"
    elif _type == TYPE_STRING:
        type_name = "TYPE_STRING"
    elif _type == TYPE_FLOAT:
        type_name = "TYPE_FLOAT"
    elif _type == TYPE_DIMENSION:
        type_name = "TYPE_DIMENSION"
    elif _type == TYPE_FRACTION:
        type_name = "TYPE_FRACTION"
    elif _type == TYPE_DYNAMIC_REFERENCE:
        type_name = "TYPE_DYNAMIC_REFERENCE"
    elif _type == TYPE_DYNAMIC_ATTRIBUTE:
        type_name = "TYPE_DYNAMIC_ATTRIBUTE"
    elif _type == TYPE_INT_DEC:
        type_name = "TYPE_INT_DEC"
    elif _type == TYPE_INT_HEX:
        type_name = "TYPE_INT_HEX"
    elif _type == TYPE_INT_BOOLEAN:
        type_name = "TYPE_INT_BOOLEAN"
    elif _type == TYPE_INT_COLOR_ARGB8:
        type_name = "TYPE_INT_COLOR_ARGB8"
    elif _type == TYPE_INT_COLOR_RGB8:
        type_name = "TYPE_INT_COLOR_RGB8"
    elif _type == TYPE_INT_COLOR_ARGB4:
        type_name = "TYPE_INT_COLOR_ARGB4"
    elif _type == TYPE_INT_COLOR_RGB4:
        type_name = "TYPE_INT_COLOR_RGB4"
    elif _type == TYPE_LAST_COLOR_INT:
        type_name = "TYPE_LAST_COLOR_INT"
    elif _type == TYPE_LAST_INT:
        type_name = "TYPE_LAST_INT"
    logger.debug(f"_type: {_type}: {type_name}: {TYPE_TABLE[_type]}")

    if _type == TYPE_STRING:
        return lookup_string(_data)

    elif _type == TYPE_ATTRIBUTE:
        return "?{}{:08X}".format(fmt_package(_data), _data)

    elif _type == TYPE_REFERENCE:
        return "@{}{:08X}".format(fmt_package(_data), _data)

    elif _type == TYPE_FLOAT:
        return "%f" % unpack("=f", pack("=L", _data))[0]

    elif _type == TYPE_INT_HEX:
        return "0x%08X" % _data

    elif _type == TYPE_INT_BOOLEAN:
        if _data == 0:
            return "false"
        return "true"

    elif _type == TYPE_DIMENSION:
        return "{:f}{}".format(
            complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK]
        )

    elif _type == TYPE_FRACTION:
        return "{:f}{}".format(
            complexToFloat(_data) * 100,
            FRACTION_UNITS[_data & COMPLEX_UNIT_MASK],
        )

    elif TYPE_FIRST_COLOR_INT <= _type <= TYPE_LAST_COLOR_INT:
        return "#%08X" % _data

    elif TYPE_FIRST_INT <= _type <= TYPE_LAST_INT:
        return "%d" % fmt_int(_data)

    return "<0x{:X}, type 0x{:02X}>".format(_data, _type)

class AXMLPrinter:
    """
    Converter for AXML Files into a lxml ElementTree, which can easily be
    converted into XML.

    A Reference Implementation can be found at http://androidxref.com/9.0.0_r3/xref/frameworks/base/tools/aapt/XMLNode.cpp
    """

    __charrange = None
    __replacement = None

    def __init__(self, raw_buff: bytes) -> bytes:
        logger.debug("AXMLPrinter")

        self.axml = AXMLParser(raw_buff)

        self.root = None
        self.packerwarning = False
        cur = []

        while self.axml.is_valid():
            _type = next(self.axml)

            type_name = "WRONG"
            if _type == START_DOCUMENT:
                type_name = "START_DOCUMENT"
            elif _type == END_DOCUMENT:
                type_name = "END_DOCUMENT"
            elif _type == START_TAG:
                type_name = "START_TAG"
            elif _type == END_TAG:
                type_name = "END_TAG"
            elif _type == TEXT:
                type_name = "TEXT"

            logger.debug(f"DEBUG ARSC TYPE {_type}: {type_name}")

            if _type == START_TAG:
                if not self.axml.get_name():  # Check if the name is empty
                    logger.error("Empty tag name, skipping to next element")
                    continue  # Skip this iteration
                uri = self._print_namespace(self.axml.get_namespace())
                uri, name = self._fix_name(uri, self.axml.get_name())
                tag = "{}{}".format(uri, name)

                comment = self.axml.get_comment()
                if comment:
                    if self.root is None:
                        logger.warning(
                            "Can not attach comment with content '{}' without root!".format(
                                comment
                            )
                        )
                    else:
                        cur[-1].append(etree.Comment(comment))

                logger.debug(
                    "START_TAG: {} (line={})".format(
                        tag, self.axml.m_lineNumber
                    )
                )

                try:
                    elem = etree.Element(tag, nsmap=self.axml.get_nsmap())
                except ValueError as e:
                    logger.error(e)
                    # nsmap= {'<!--': 'http://schemas.android.com/apk/res/android'} | pull/1056
                    if 'Invalid namespace prefix' in str(e):
                        corrected_nsmap = self.clean_and_replace_nsmap(
                            self.axml.get_nsmap(), str(e).split("'")[1]
                        )
                        elem = etree.Element(tag, nsmap=corrected_nsmap)
                    else:
                        raise

                for i in range(self.axml.getAttributeCount()):
                    uri = self._print_namespace(
                        self.axml.getAttributeNamespace(i)
                    )
                    uri, name = self._fix_name(
                        uri, self.axml.getAttributeName(i)
                    )
                    value = self._fix_value(self._get_attribute_value(i))

                    logger.debug(
                        "found an attribute: {}{}='{}'".format(
                            uri, name, value.encode("utf-8")
                        )
                    )
                    if "{}{}".format(uri, name) in elem.attrib:
                        logger.warning(
                            "Duplicate attribute '{}{}'! Will overwrite!".format(
                                uri, name
                            )
                        )
                    elem.set("{}{}".format(uri, name), value)

                if self.root is None:
                    self.root = elem
                else:
                    if not cur:
                        # looks like we lost the root?
                        logger.error(
                            "No more elements available to attach to! Is the XML malformed?"
                        )
                        break
                    cur[-1].append(elem)
                cur.append(elem)

            if _type == END_TAG:
                if not cur:
                    logger.error(
                        "Too many END_TAG! No more elements available to attach to!"
                    )
                else:
                    if not self.axml.get_name():  # Check if the name is empty
                        logger.error(
                            "Empty tag name at END_TAG, skipping to next element"
                        )
                        continue

                name = self.axml.get_name()
                uri = self._print_namespace(self.axml.get_namespace())
                tag = "{}{}".format(uri, name)
                if cur[-1].tag != tag:
                    logger.warning(
                        "Closing tag '{}' does not match current stack! At line number: {}. Is the XML malformed?".format(
                            self.axml.get_name(), self.axml.m_lineNumber
                        )
                    )
                cur.pop()
            if _type == TEXT:
                logger.debug("TEXT for {}".format(cur[-1]))
                cur[-1].text = self.axml.get_text()
            if _type == END_DOCUMENT:
                # Check if all namespace mappings are closed
                if len(self.axml.namespaces) > 0:
                    logger.warning(
                        "Not all namespace mappings were closed! Malformed AXML?"
                    )
                break

    def clean_and_replace_nsmap(self, nsmap, invalid_prefix):
        correct_prefix = 'android'
        corrected_nsmap = {}
        for prefix, uri in nsmap.items():
            if prefix.startswith(invalid_prefix):
                corrected_nsmap[correct_prefix] = uri
            else:
                corrected_nsmap[prefix] = uri
        return corrected_nsmap

    def get_buff(self) -> bytes:
        """
        Returns the raw XML file without prettification applied.

        :returns: bytes, encoded as UTF-8
        """
        return self.get_xml(pretty=False)

    def get_xml(self, pretty: bool = True) -> bytes:
        """
        Get the XML as an UTF-8 string

        :returns: bytes encoded as UTF-8
        """
        return etree.tostring(self.root, encoding="utf-8", pretty_print=pretty)

    def get_xml_obj(self) -> etree.Element:
        """
        Get the XML as an ElementTree object

        :returns: `lxml.etree.Element` object
        """
        return self.root

    def is_valid(self) -> bool:
        """
        Return the state of the [AXMLParser][androguard.core.axml.AXMLParser].
        If this flag is set to `False`, the parsing has failed, thus
        the resulting XML will not work or will even be empty.

        :returns: `True` if the `AXMLParser` finished parsing, or `False` if an error occurred
        """
        return self.axml.is_valid()

    def is_packed(self) -> bool:
        """
        Returns True if the AXML is likely to be packed

        Packers do some weird stuff and we try to detect it.
        Sometimes the files are not packed but simply broken or compiled with
        some broken version of a tool.
        Some file corruption might also be appear to be a packed file.

        :returns: True if packer detected, False otherwise
        """
        return self.packerwarning or self.axml.packerwarning

    def _get_attribute_value(self, index: int):
        """
        Wrapper function for format_value to resolve the actual value of an attribute in a tag
        :param index: index of the current attribute
        :return: formatted value
        """
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        return format_value(
            _type, _data, lambda _: self.axml.getAttributeValue(index)
        )

    def _fix_name(self, prefix, name) -> tuple[str, str]:
        """
        Apply some fixes to element named and attribute names.
        Try to get conform to:
        > Like element names, attribute names are case-sensitive and must start with a letter or underscore.
        > The rest of the name can contain letters, digits, hyphens, underscores, and periods.
        See: <https://msdn.microsoft.com/en-us/library/ms256152(v=vs.110).aspx>

        This function tries to fix some broken namespace mappings.
        In some cases, the namespace prefix is inside the name and not in the prefix field.
        Then, the tag name will usually look like 'android:foobar'.
        If and only if the namespace prefix is inside the namespace mapping and the actual prefix field is empty,
        we will strip the prefix from the attribute name and return the fixed prefix URI instead.
        Otherwise replacement rules will be applied.

        The replacement rules work in that way, that all unwanted characters are replaced by underscores.
        In other words, all characters except the ones listed above are replaced.

        :param name: Name of the attribute or tag
        :param prefix: The existing prefix uri as found in the AXML chunk
        :return: a fixed version of prefix and name
        """
        if not name[0].isalpha() and name[0] != "_":
            logger.warning(
                "Invalid start for name '{}'. "
                "XML name must start with a letter.".format(name)
            )
            self.packerwarning = True
            name = "_{}".format(name)
        if (
            name.startswith("android:")
            and prefix == ''
            and 'android' in self.axml.get_nsmap()
        ):
            # Seems be a common thing...
            logger.info(
                "Name '{}' starts with 'android:' prefix but 'android' is a known prefix. Replacing prefix.".format(
                    name
                )
            )
            prefix = self._print_namespace(self.axml.get_nsmap()['android'])
            name = name[len("android:") :]
            # It looks like this is some kind of packer... Not sure though.
            self.packerwarning = True
        elif ":" in name and prefix == '':
            self.packerwarning = True
            embedded_prefix, new_name = name.split(":", 1)
            if embedded_prefix in self.axml.get_nsmap():
                logger.info(
                    "Prefix '{}' is in namespace mapping, assume that it is a prefix."
                )
                prefix = self._print_namespace(
                    self.axml.get_nsmap()[embedded_prefix]
                )
                name = new_name
            else:
                # Print out an extra warning
                logger.warning(
                    "Confused: name contains a unknown namespace prefix: '{}'. "
                    "This is either a broken AXML file or some attempt to break stuff.".format(
                        name
                    )
                )
        if not re.match(r"^[a-zA-Z0-9._-]*$", name):
            logger.warning(
                "Name '{}' contains invalid characters!".format(name)
            )
            self.packerwarning = True
            name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)

        return prefix, name

    def _fix_value(self, value):
        """
        Return a cleaned version of a value
        according to the specification:
        > Char	   ::=   	#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]

        See <https://www.w3.org/TR/xml/#charsets>

        :param value: a value to clean
        :return: the cleaned value
        """
        if not self.__charrange or not self.__replacement:
            self.__charrange = re.compile(
                '^[\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]*$'
            )
            self.__replacement = re.compile(
                '[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]'
            )

        # Reading string until \x00. This is the same as aapt does.
        if "\x00" in value:
            self.packerwarning = True
            logger.warning(
                "Null byte found in attribute value at position {}: "
                "Value(hex): '{}'".format(
                    value.find("\x00"), binascii.hexlify(value.encode("utf-8"))
                )
            )
            value = value[: value.find("\x00")]

        if not self.__charrange.match(value):
            logger.warning(
                "Invalid character in value found. Replacing with '_'."
            )
            self.packerwarning = True
            value = self.__replacement.sub('_', value)
        return value

    def _print_namespace(self, uri):
        if uri != "":
            uri = "{{{}}}".format(uri)
        return uri

class AXMLEncoder:
    STRING_POOL_HEADER_SIZE = 0x1C

    def __init__(self, xml: str):
        self.tree = etree.fromstring(xml)

        # in aapt first we add attributes with resid assigned.
        # for manifest these are all atributes with public namespace.
        # so basically all attributes that start with 'android:'
        self.namespaces = self.tree.nsmap
        self.attrs_with_nsp = []
        self.strings = []
        self.strings += [''] # adding empty tag name as in aapt, but it still doesn't make sense to me
        for element in self.tree.iter():
            print(f"{element.sourceline}: {element.tag} - {element.attrib}")
            RESOURCES_ROOT_NAMESPACE = "http://schemas.android.com/apk/res/";
            for attr in element.keys():
                parts = attr.split('}')
                namespace = None
                if len(parts) == 2:
                    namespace = parts[0][1:]
                name = parts[-1]
                if (namespace and 
                    namespace.startswith(RESOURCES_ROOT_NAMESPACE) and 
                    name not in self.attrs_with_nsp):
                    self.attrs_with_nsp += [name]
                elif (name not in self.strings and
                      name not in self.attrs_with_nsp):
                    self.strings += [name]
            self.strings += [element.tag]

            for val in element.values():
                if (val not in self.strings and
                    val not in self.attrs_with_nsp):
                    self.strings += [val]
        self.string_pool = []
        self.string_pool += self.attrs_with_nsp
        for (k, v) in self.namespaces.items():
            self.string_pool += [k]
            self.string_pool += [v]
        self.string_pool += self.strings
        print(self.string_pool)
        self.buffer = io.BytesIO()
        sys.exit(1)
        self.axml_size = ARSCHeader.SIZE

        self.string_pool_size = ARSCHeader.SIZE
        self.string_count = 0
        self.string_pool_size += 4
        self.style_count = 0
        self.string_pool_size += 4
        self.flags = 0
        self.string_pool_size += 4
        self.strings_offset = self.STRING_POOL_HEADER_SIZE
        self.string_pool_size += 4
        self.styles_offset = 0
        self.string_pool_size += 4
        self.string_offsets = []
        for i in range(self.string_count):
            self.string_offsets += [0]
            self.string_pool_size += 4
        self.style_offsets = []
        for i in range(self.style_count):
            self.style_offsets += [0]
            self.string_pool_size += 4

        self.axml_size += self.string_pool_size

        self.m_resourceIDs = []
        self.resource_map_size = ARSCHeader.SIZE
        self.axml_size += self.resource_map_size

        self.xml_namespace_size = ARSCHeader.SIZE
        self.xml_namespace_line_number = self.tree.sourceline
        self.xml_namespace_size += 4
        self.xml_namespace_comment_index = 0xFFFFFFFF
        self.xml_namespace_size += 4
        self.xml_namespace_prefix = 0
        self.xml_namespace_size += 4
        self.xml_namespace_uri = 0
        self.xml_namespace_size += 4
        self.axml_size += self.xml_namespace_size

        self.xml_root_size = ARSCHeader.SIZE
        self.xml_root_line_number = 0
        self.xml_root_size += 4
        self.xml_root_comment_index = 0
        self.xml_root_size += 4
        self.xml_root_namespace_uri = 0
        self.xml_root_size += 4
        self.xml_root_name = 0
        self.xml_root_size += 4
        self.xml_root_at_start = 0
        self.xml_root_size += 2
        self.xml_root_at_size = 0
        self.xml_root_size += 2
        self.xml_root_attribute_count = 0
        self.xml_root_size += 4
        self.xml_root_class_attribute = 0
        self.xml_root_size += 4
        self.axml_size += self.xml_root_size

        self.xml_end_root_size = ARSCHeader.SIZE
        self.xml_end_root_line_number = 0
        self.xml_end_root_size += 4
        self.xml_end_root_comment_index = 0
        self.xml_end_root_size += 4
        self.xml_end_root_namespace_uri = 0
        self.xml_end_root_size += 4
        self.xml_end_root_name = 0
        self.xml_end_root_size += 4
        self.axml_size += self.xml_end_root_size

        self.xml_end_namespace_size = ARSCHeader.SIZE
        self.xml_end_namespace_line_number = 0
        self.xml_end_namespace_size += 4
        self.xml_end_namespace_comment_index = 0xFFFFFFFF
        self.xml_end_namespace_size += 4
        self.xml_end_namespace_prefix = 0
        self.xml_end_namespace_size += 4
        self.xml_end_namespace_uri = 0
        self.xml_end_namespace_size += 4
        self.axml_size += self.xml_end_namespace_size

        # writing first ARSCHeader
        self.write_ResChunk_header(RES_XML_TYPE, ARSCHeader.SIZE, self.axml_size)

        # writing STRING POOL
        self.write_ResStringPool_header(self.string_pool_size)

        # Writing Resource Map
        self.write_ResChunk_header(RES_XML_RESOURCE_MAP_TYPE, ARSCHeader.SIZE, self.resource_map_size)

        # Writing namespace mapping
        self.write_ResChunk_header(RES_XML_START_NAMESPACE_TYPE, 0x10, self.xml_namespace_size)
        self.buffer.write(pack("<L", self.xml_namespace_line_number))
        self.buffer.write(pack("<L", self.xml_namespace_comment_index))
        self.buffer.write(pack("<L", self.xml_namespace_prefix))
        self.buffer.write(pack("<L", self.xml_namespace_uri))

        # Write XML root
        self.write_ResChunk_header(RES_XML_START_ELEMENT_TYPE, 0x10, self.xml_root_size)
        self.buffer.write(pack("<L", self.xml_root_line_number))
        self.buffer.write(pack("<L", self.xml_root_comment_index))
        self.buffer.write(pack("<L", self.xml_root_namespace_uri))
        self.buffer.write(pack("<L", self.xml_root_name))
        self.buffer.write(pack("<H", self.xml_root_at_start))
        self.buffer.write(pack("<H", self.xml_root_at_size))
        self.buffer.write(pack("<L", self.xml_root_attribute_count))
        self.buffer.write(pack("<L", self.xml_root_class_attribute))

        # Write END XML root
        self.write_ResChunk_header(RES_XML_END_ELEMENT_TYPE, 0x10, self.xml_end_root_size)
        self.buffer.write(pack("<L", self.xml_end_root_line_number))
        self.buffer.write(pack("<L", self.xml_end_root_comment_index))
        self.buffer.write(pack("<L", self.xml_end_root_namespace_uri))
        self.buffer.write(pack("<L", self.xml_end_root_name))

        # Writing END namespace mapping
        self.write_ResChunk_header(RES_XML_END_NAMESPACE_TYPE, 0x10, self.xml_end_namespace_size)
        self.buffer.write(pack("<L", self.xml_end_namespace_line_number))
        self.buffer.write(pack("<L", self.xml_end_namespace_comment_index))
        self.buffer.write(pack("<L", self.xml_end_namespace_prefix))
        self.buffer.write(pack("<L", self.xml_end_namespace_uri))

    def get_bytes(self):
        return self.buffer.getbuffer().tobytes()

    def write_ResChunk_header(self, type_id, headerSize, size):
        self.buffer.write(pack("<H", type_id))
        self.buffer.write(pack("<H", headerSize))
        self.buffer.write(pack("<L", size))

    def write_ResStringPool_header(self, size):
        self.write_ResChunk_header(RES_STRING_POOL_TYPE, self.STRING_POOL_HEADER_SIZE, size)
        self.buffer.write(pack("<I", self.string_count))
        self.buffer.write(pack("<I", self.style_count))
        self.buffer.write(pack("<I", self.flags))
        self.buffer.write(pack("<I", self.strings_offset))
        self.buffer.write(pack("<I", self.styles_offset))
        for i in range(self.string_count):
            self.buffer.write(pack("<I", self.string_offsets[i]))
        for i in range(self.style_count):
            self.buffer.write(pack("<I", self.style_offsets[i]))

with open("tiny-android-template/build/AndroidManifest.xml", "rb") as fp:
    a = AXMLPrinter(fp.read())

print("\n\n\n", flush=True)
print("=======================================================", flush=True)
print("DECODED", flush=True)
print("=======================================================", flush=True)
print(a.get_xml().decode("utf-8"), flush=True)

print("\n\n\n", flush=True)
print("=======================================================", flush=True)
print("ENCODING", flush=True)
print("=======================================================", flush=True)
encoded = AXMLEncoder(a.get_xml().decode("utf-8")).get_bytes()

print("\n\n\n", flush=True)
print("=======================================================", flush=True)
print("DECODING ENCODED", flush=True)
print("=======================================================", flush=True)
print(AXMLPrinter(encoded).get_xml().decode("utf-8"), flush=True)

# try also to read xml from file after that
