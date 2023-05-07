import os
import sys
import re
import datetime
import subprocess


#####################################################
# pcapngフォーマットに関する定義
#####################################################
BLOCK_TYPE_SIZE           = 4
BLOCK_LEN_SIZE            = 4

BLOCK_TYPE_SHB            = 0x0A0D0D0A
BLOCK_TYPE_IDB            = 0x00000001
BLOCK_TYPE_EPB            = 0x00000006

SHB_MAGIC_SIZE            = 4
SHB_VER_SIZE              = 2
SHB_SECTION_LEN_SIZE      = 8
SHB_MAGIC_NUM             = 0x1A2B3C4D
SHB_READ_LEN              = 24

IDB_LINKTYPE_SIZE         = 2
IDB_RESERVE_SIZE          = 2
IDB_SNAP_LEN_SIZE         = 4
IDB_READ_LEN              = 16

LINKTYPE_USBPCAP          = 249     # https://www.ietf.org/id/draft-ietf-opsawg-pcaplinktype-00.html

EPB_INTERFACE_ID_SIZE     = 4
EPB_TIMESTAMP_SIZE        = 4
EPB_CAPTURE_LEN_SIZE      = 4
EPB_PACKET_LEN_SIZE       = 4
EPB_READ_LEN              = 28



#####################################################
# USBPcapのログに関する定義
#####################################################
USBPCAP_HEADER_LEN_SIZE   = 2
USBPCAP_IRP_ID_SIZE       = 8
USBPCAP_IRP_USBD_ST_SIZE  = 4
USBPCAP_URB_FUNC_SIZE     = 2
USBPCAP_IRP_INFO_SIZE     = 1
USBPCAP_BUS_ID_SIZE       = 2
USBPCAP_DEV_ADDR_SIZE     = 2
USBPCAP_ENDPOINT_SIZE     = 1
USBPCAP_TRANS_TYPE_SIZE   = 1
USBPCAP_PACKET_LEN_SIZE   = 4
USBPCAP_CTRL_STAGE_SIZE   = 1

USBPCAP_CTRL_BMREQ_SIZE   = 1
USBPCAP_CTRL_REQ_SIZE     = 1

USB_TRANS_TYPE_ISOC       = 0
USB_TRANS_TYPE_INTR       = 1
USB_TRANS_TYPE_CTRL       = 2
USB_TRANS_TYPE_BULK       = 3
USB_TRANS_TYPE_ABORT_PIPE = 254

USB_FUNC_SELECT_CFG       = 0x0000
USB_FUNC_TRANSFER         = 0x0008
USB_FUNC_GET_DESC         = 0x000b
USB_FUNC_GET_STATUS       = 0x0013
USB_FUNC_CLASS_DEV        = 0x001a
USB_FUNC_CTRL_TRANS_EX    = 0x0032

USB_ENDPOINT_ATTR_CTRL    = 0
USB_ENDPOINT_ATTR_ISOC    = 1
USB_ENDPOINT_ATTR_BULK    = 2
USB_ENDPOINT_ATTR_INTR    = 3


#####################################################
# USBのCTRL転送に関する定義
#####################################################
USB_CTRL_REQ_GET_ST   = 0
USB_CTRL_REQ_CLR_FT   = 1
USB_CTRL_REQ_SET_FT   = 3
USB_CTRL_REQ_SET_ADDR = 5
USB_CTRL_REQ_GET_DESC = 6
USB_CTRL_REQ_SET_DESC = 7
USB_CTRL_REQ_GET_CFG  = 8
USB_CTRL_REQ_SET_CFG  = 9
USB_CTRL_REQ_GET_ITF  = 10
USB_CTRL_REQ_SET_ITF  = 11
USB_CTRL_REQ_SYNC_FRM = 12

USB_DESC_TYPE_DEVICE      = 1
USB_DESC_TYPE_CONFIG      = 2
USB_DESC_TYPE_STRING      = 3
USB_DESC_TYPE_INTERFACE   = 4
USB_DESC_TYPE_ENDPOINT    = 5
USB_DESC_TYPE_DEVICE_Q    = 6
USB_DESC_TYPE_OTHER_SPD   = 7
USB_DESC_TYPE_INTERFACE_P = 8

USB_INTERFACE_CLASS_AUDIO               = 1
USB_INTERFACE_CLASS_CDC                 = 2
USB_INTERFACE_CLASS_HID                 = 3
USB_INTERFACE_CLASS_IMAGE               = 6
USB_INTERFACE_CLASS_MSC                 = 8
USB_INTERFACE_CLASS_HUB                 = 9
USB_INTERFACE_CLASS_WIRELESS_CONTROLLER = 0xE0
USB_INTERFACE_CLASS_VENDOR_SPECIFIC     = 0xFF

MIN_ENDPOINT_DESC_SIZE    = 7


EOF                       = -1


g_sections                = []



class cUSBEndpoint:
    def __init__(self, parent, EndpointAddress):
        self.parent             = parent           #cUSBInterfaceクラスへの参照
        self.EndpointAddress    = EndpointAddress
        self.mAttributes        = 0
        self.MaxPacketSize      = 0
        self.Interval           = 0


class cUSBInterface:
    def __init__(self, parent, InterfaceNumber):
        self.parent             = parent           #cUSBConfigクラスへの参照
        self.InterfaceNumber    = InterfaceNumber
        self.NumEndpoints       = 0
        self.InterfaceClass     = 0
        self.InterfaceSubClass  = 0
        self.InterfaceProtocol  = 0
        self.Endpoints          = []

    def get_usb_endpoint(self, EndpointAddress):
        for endpoint in self.Endpoints:
            if (endpoint.EndpointAddress == EndpointAddress):
                return endpoint

        endpoint = cUSBEndpoint(self, EndpointAddress)
        self.Endpoints.append(endpoint)
        return endpoint


class cUSBConfig:
    def __init__(self, parent, ConfigurationValue):
        self.parent             = parent           #cUSBDeviceクラスへの参照
        self.NumInterfaces      = 0
        self.ConfigurationValue = ConfigurationValue
        self.mAttributes        = 0
        self.MaxPower           = 0
        self.Interfaces         = []

    def get_usb_interface(self, InterfaceNumber):
        for interface in self.Interfaces:
            if (interface.InterfaceNumber == InterfaceNumber):
                return interface

        interface = cUSBInterface(self, InterfaceNumber)
        self.Interfaces.append(interface)
        return interface


class cUSBDevice:
    def __init__(self, bus_id, address):
        self.bus_id            = bus_id
        self.address           = address
        self.endpoint          = []
        self.InterfaceClass    = ""
        self.NumConfigurations = 0
        self.vid               = 0
        self.pid               = 0
        self.packets           = []
        self.configs           = []

    def add_packet(self, packet):
        self.packets.append(packet)

    def get_last_packet(self):
        if (len(self.packets) > 0):
            return self.packets[-1]

        packet = cUSBPcapHeader(None)
        return packet

    def get_usb_config(self, ConfigurationValue):
        for config in self.configs:
            if (config.ConfigurationValue == ConfigurationValue):
                return config

        config = cUSBConfig(self, ConfigurationValue)
        self.configs.append(config)
        return config

#####################################################
# USB Pcap packet
#####################################################
class cUSBPcapHeader:
    def __init__(self, parent):
        self.length       = 0
        self.irp_id       = 0
        self.usbd_st      = 0
        self.urb_function = 0
        self.irp_info     = 0
        self.bus_id       = 0
        self.dev_addr     = 0
        self.endpoint     = 0
        self.trans_type   = 0
        self.packet_len   = 0
        self.parent       = parent           #cEPBクラスへの参照
        self.bytes_read   = 0

    def read_header_element(self, size):
        parent = self.parent
        grandpa = parent.parent

        tmp_data = grandpa.file.read(size)
#       print("tmp_data[%02d:%02d] : " % (self.bytes_read, size), tmp_data)
        self.bytes_read += size
        return int.from_bytes(tmp_data, byteorder=grandpa.byte_order)


    def read_desc_header(self, last):
        self.DescLength = self.read_header_element(1)
        self.DescType   = self.read_header_element(1)
        if (self.DescType != last.DescType):
            print("Strange Get Desc response!")

        return

    def read_device_desc(self, usb):
        self.bcdUSB             = self.read_header_element(2)
        self.bDeviceClass       = self.read_header_element(1)
        self.bDeviceSubClass    = self.read_header_element(1)
        self.bDeviceProtocol    = self.read_header_element(1)
        self.bMaxPacketSize0    = self.read_header_element(1)
        self.idVendor           = self.read_header_element(2)
        self.idProduct          = self.read_header_element(2)
        self.bcdDevice          = self.read_header_element(2)
        self.iManufacturer      = self.read_header_element(1)
        self.iProduct           = self.read_header_element(1)
        self.iSerialNumber      = self.read_header_element(1)
        self.bNumConfigurations = self.read_header_element(1)

        print("Get Desc response vid:0x%04x, pid:0x%04x" % (self.idVendor, self.idProduct))
        usb.vid               = self.idVendor
        usb.pid               = self.idProduct
        usb.NumConfigurations = self.bNumConfigurations
        return

    def read_config_desc(self, remain, usb):
        print("read_config_desc remain : 0x%02x, bytes_read : %d" % (remain, self.bytes_read))
        self.wTotalLength        = self.read_header_element(2)
        bytes_to_go = self.wTotalLength - 4
        start_bytes_read = self.bytes_read
        print("  bytes to go %d, start : %d" % (bytes_to_go, start_bytes_read))

        self.bNumInterfaces      = self.read_header_element(1)
        self.bConfigurationValue = self.read_header_element(1)
        self.iConfiguration      = self.read_header_element(1)
        self.bmAttributes        = self.read_header_element(1)
        self.bMaxPower           = self.read_header_element(1)

        config = usb.get_usb_config(self.bConfigurationValue)
        config.NumInterfaces      = self.bNumInterfaces
        config.ConfigurationValue = self.bConfigurationValue
        config.mAttributes        = self.bmAttributes
        config.MaxPower           = self.bMaxPower
        if (remain > bytes_to_go + start_bytes_read):
            interface = None
            while (bytes_to_go > self.bytes_read - start_bytes_read):
#               print("Additional Descriptor in Config Descriptor bytes_read : %d, remain : %d" % (self.bytes_read, remain))
                DescLength = self.read_header_element(1)
                DescType   = self.read_header_element(1)
                print("Additional Descriptor in Config Descriptor Type : 0x%02x, Len : %d, bytes_read : %d, remain : %d" % (DescType, DescLength, self.bytes_read, remain))
                if (USB_DESC_TYPE_INTERFACE == DescType):
                    InterfaceNumber   = self.read_header_element(1)
                    AlternateSetting  = self.read_header_element(1)
                    NumEndpoints      = self.read_header_element(1)
                    InterfaceClass    = self.read_header_element(1)
                    InterfaceSubClass = self.read_header_element(1)
                    InterfaceProtocol = self.read_header_element(1)
                    iInterface        = self.read_header_element(1)
                    if (DescLength != 9):
                        print("Strange Interface Descriptor size! : %d" % DescLength)

                    interface = config.get_usb_interface(InterfaceNumber)
                    interface.NumEndpoints      = NumEndpoints
                    interface.InterfaceClass    = InterfaceClass
                    interface.InterfaceSubClass = InterfaceSubClass
                    interface.InterfaceProtocol = InterfaceProtocol


                elif (USB_DESC_TYPE_ENDPOINT == DescType):
                    EndpointAddress   = self.read_header_element(1)
                    mAttributes       = self.read_header_element(1)
                    MaxPacketSize     = self.read_header_element(2)
                    Interval          = self.read_header_element(1)

                    desc_remain = DescLength - MIN_ENDPOINT_DESC_SIZE
                    while (desc_remain > 0):
                        self.read_header_element(1)
                        desc_remain -= 1

                    if (interface == None):
                        print("Strange Endpoint Descriptor! without interface!")
                    else:
                        endpoint = interface.get_usb_endpoint(EndpointAddress)
                        endpoint.mAttributes   = mAttributes
                        endpoint.MaxPacketSize = MaxPacketSize
                        endpoint.Interval      = Interval
                else:
                    print("Other Type Descriptor : 0x%02x" % DescType)
                    desc_remain = DescLength - 2
                    while (desc_remain > 0):
                        self.read_header_element(1)
                        desc_remain -= 1

        return

    def read_get_desc_res(self, remain, usb, last):
        self.read_desc_header(last)

        print("read_get_desc_res remain : 0x%02x, type : %d" % (remain, self.DescType))
        if (USB_DESC_TYPE_DEVICE == self.DescType):
            self.read_device_desc(usb)
        elif (USB_DESC_TYPE_CONFIG == self.DescType):
            self.read_config_desc(remain, usb)
        return


    def read_packet(self, remain):
        parent = self.parent
        grandpa = parent.parent

        self.length       = self.read_header_element(USBPCAP_HEADER_LEN_SIZE)
        self.irp_id       = self.read_header_element(USBPCAP_IRP_ID_SIZE)
        self.usbd_st      = self.read_header_element(USBPCAP_IRP_USBD_ST_SIZE)
        self.urb_function = self.read_header_element(USBPCAP_URB_FUNC_SIZE)
        self.irp_info     = self.read_header_element(USBPCAP_IRP_INFO_SIZE)
        self.bus_id       = self.read_header_element(USBPCAP_BUS_ID_SIZE)
        self.dev_addr     = self.read_header_element(USBPCAP_DEV_ADDR_SIZE)
        self.endpoint     = self.read_header_element(USBPCAP_ENDPOINT_SIZE)
        self.trans_type   = self.read_header_element(USBPCAP_TRANS_TYPE_SIZE)
        self.packet_len   = self.read_header_element(USBPCAP_PACKET_LEN_SIZE)

        usb = grandpa.get_usb_device(self.bus_id, self.dev_addr)
        last = usb.get_last_packet()

        if (self.trans_type == USB_TRANS_TYPE_CTRL):
            self.ctrl_stage    = self.read_header_element(USBPCAP_CTRL_STAGE_SIZE)

            if (self.irp_info == 0):
                # Host → Deviceの場合は、bmRequestType、bRequestを読み出す
                self.mRequestType = self.read_header_element(USBPCAP_CTRL_BMREQ_SIZE)
                self.Request      = self.read_header_element(USBPCAP_CTRL_REQ_SIZE)

                if (USB_CTRL_REQ_GET_DESC == self.Request):
                    self.DescIndex = self.read_header_element(1)
                    self.DescType  = self.read_header_element(1)
                elif (USB_CTRL_REQ_SET_CFG == self.Request):
                    self.ConfigValue = self.read_header_element(1)
            else:
                if (last.trans_type == USB_TRANS_TYPE_CTRL):
                    if (USB_CTRL_REQ_GET_DESC == last.Request):
                        self.read_get_desc_res(remain, usb, last)


        self.data = self.parent.parent.file.read(remain - self.bytes_read)

        usb.add_packet(self)
        return

    def disp_packet(self):
        parent = self.parent
        print("read EPB(USBPcap) block! length : %3d, Interface : %d, TS[%08x-%08x]" % (parent.total_len, parent.interface_id, parent.time_stamp_h, parent.time_stamp_l))

        addr = "[%02x:%02x:%02x]" % (self.bus_id, self.dev_addr, self.endpoint)
        extra = ""

        if (self.trans_type == USB_TRANS_TYPE_ISOC):
            transfer = "ISOC "
        elif (self.trans_type == USB_TRANS_TYPE_INTR):
            transfer = "INTR "
        elif (self.trans_type == USB_TRANS_TYPE_CTRL):
            transfer = "CTRL "
        elif (self.trans_type == USB_TRANS_TYPE_BULK):
            transfer = "BULK "
        elif (self.trans_type == USB_TRANS_TYPE_ABORT_PIPE):
            transfer = "ABORT"
        else:
            transfer = "OTHER(%d)" % self.trans_type

        if (self.endpoint & 0x80):
            transfer += " IN "
        else:
            transfer += " OUT"

        if (self.irp_info == 0):
            transfer += " --> "
        elif (self.irp_info == 1):
            transfer += " <-- "
        else:
            transfer += " ??? "

        print("  %s %s" % (transfer, addr))
        return


#####################################################
# Any other packets
#####################################################
class cPacket:
    def __init__(self, parent):
        self.length       = 0
        self.parent       = parent           #cEPBクラスへの参照

    def read_packet(self, remain):
        self.data = self.parent.parent.file.read(remain)
        return

    def disp_packet(self):
        parent = self.parent
        print("read EPB block! length : %d, Interface : %d, TS[%08x-%08x]" % (parent.total_len, parent.interface_id, parent.time_stamp_h, parent.time_stamp_l))
        return


#####################################################
# Section Header Block
#####################################################
class cSHB:
    def __init__(self, parent):
        self.block_type  = 0
        self.total_len   = 0
        self.magic       = 0
        self.ver_minor   = 0
        self.ver_major   = 0
        self.section_len = 0
        self.parent      = parent           #cSectionクラスへの参照


#####################################################
# Interface Description Block
#####################################################
class cIDB:
    def __init__(self, parent, length):
        self.block_type  = BLOCK_TYPE_IDB
        self.total_len   = length
        self.link_type   = 0
        self.snap_len    = 0
        self.parent      = parent           #cSectionクラスへの参照

    def read_block(self):
        data_lt      = self.parent.file.read(IDB_LINKTYPE_SIZE)
        data_waste   = self.parent.file.read(IDB_RESERVE_SIZE)
        data_snaplen = self.parent.file.read(IDB_SNAP_LEN_SIZE)

        self.link_type = int.from_bytes(data_lt, byteorder=self.parent.byte_order)
        self.snap_len  = int.from_bytes(data_snaplen, byteorder=self.parent.byte_order)

        data_waste = self.parent.file.read(self.total_len - IDB_READ_LEN - BLOCK_LEN_SIZE)
        return

    def disp_block(self):
        print("read IDB block! length : %d, link_type : %d, snap_len : 0x%08x" % (self.total_len, self.link_type, self.snap_len))


#####################################################
# Enhanced Packet Block
#####################################################
class cEPB:
    def __init__(self, parent, length):
        self.block_type   = BLOCK_TYPE_EPB
        self.total_len    = length
        self.interface_id = 0
        self.time_stamp_h = 0
        self.time_stamp_l = 0
        self.capture_len  = 0
        self.packet_len   = 0
        self.parent       = parent           #cSectionクラスへの参照
        self.child        = ""

    def read_block(self):
        data_iterface = self.parent.file.read(EPB_INTERFACE_ID_SIZE)
        data_ts_h     = self.parent.file.read(EPB_TIMESTAMP_SIZE)
        data_ts_l     = self.parent.file.read(EPB_TIMESTAMP_SIZE)
        data_cap_len  = self.parent.file.read(EPB_CAPTURE_LEN_SIZE)
        data_pac_len  = self.parent.file.read(EPB_PACKET_LEN_SIZE)

        self.interface_id = int.from_bytes(data_iterface, byteorder=self.parent.byte_order)
        self.time_stamp_h = int.from_bytes(data_ts_h, byteorder=self.parent.byte_order)
        self.time_stamp_l = int.from_bytes(data_ts_l, byteorder=self.parent.byte_order)
        self.capture_len  = int.from_bytes(data_cap_len, byteorder=self.parent.byte_order)
        self.packet_len   = int.from_bytes(data_pac_len, byteorder=self.parent.byte_order)

        if (self.interface_id > len(self.parent.idbs)):
            print("Invalid InterFace ID in EPB  ID : %d" % self.interface_id)
            sys.exit("error")

        if (self.parent.idbs[self.interface_id].link_type == LINKTYPE_USBPCAP):
            self.child = cUSBPcapHeader(self)
        else:
            self.child = cPacket(self)

        # EPBのヘッダ部分と末尾のLength情報を除いて、Packetデータとして読み出すべき長さをremainとして引数に渡す
        self.child.read_packet(self.total_len - EPB_READ_LEN - BLOCK_LEN_SIZE)

        return

    def disp_block(self):
         self.child.disp_packet()


#####################################################
# Any other blocks
#####################################################
class cBlock:
    def __init__(self, parent, type, length):
        self.block_type   = type
        self.total_len    = length
        self.parent       = parent           #cSectionクラスへの参照

    def read_block(self):
        data_waste = self.parent.file.read(self.total_len - BLOCK_TYPE_SIZE - BLOCK_LEN_SIZE - BLOCK_LEN_SIZE)
        return

    def disp_block(self):
        print("read block type : 0x%08x, length : %d" % (self.block_type, self.total_len))


#####################################################
# Section
#####################################################
class cSection:
    def __init__(self, file):
        self.file        = file
        self.shb         = ""
        self.idbs        = []
        self.blocks      = []
        self.byte_order  = ''
        self.usb_devices = []

    def read_shb(self):
        self.shb = cSHB(self)
        self.shb.block_type = BLOCK_TYPE_SHB

        # ブロックサイズとMAGICを読みだす
        data_len = self.file.read(BLOCK_LEN_SIZE)
        data_magic = self.file.read(SHB_MAGIC_SIZE)

        # 先にバイトオーダーを決定する
        if (SHB_MAGIC_NUM == int.from_bytes(data_magic, byteorder='little')):
            self.byte_order  = 'little'
        elif (SHB_MAGIC_NUM == int.from_bytes(data_magic, byteorder='big')):
            self.byte_order  = 'big'
        else:
            print("Invalid SHB magic number! : 0x%08x" % int.from_bytes(data_magic, byteorder='little'))
            sys.exit("error")

        self.shb.magic = SHB_MAGIC_NUM

        # 決定したバイトオーダーに従って、ブロックサイズを読み出す
        self.shb.total_len  = int.from_bytes(data_len, byteorder=self.byte_order)

        data_major       = self.file.read(SHB_VER_SIZE)
        data_minor       = self.file.read(SHB_VER_SIZE)
        data_section_len = self.file.read(SHB_SECTION_LEN_SIZE)
        self.shb.ver_major    = int.from_bytes(data_major, byteorder=self.byte_order)
        self.shb.ver_minor    = int.from_bytes(data_minor, byteorder=self.byte_order)
        self.shb.section_len  = int.from_bytes(data_section_len, byteorder=self.byte_order)

        print("read SHB block! lenght : 0x%08x, magic :0x%08x, ver : %d.%d, section length : 0x%016x" % (self.shb.total_len, self.shb.magic, self.shb.ver_major, self.shb.ver_minor, self.shb.section_len))

        data_waste = self.file.read(self.shb.total_len - SHB_READ_LEN - BLOCK_LEN_SIZE)
        data_len = self.file.read(BLOCK_LEN_SIZE)
        if (len(data_len) !=  BLOCK_LEN_SIZE):
            print("Invalid SHB block size! : 0x%08x" % self.shb.total_len)
            sys.exit("error")

        if (self.shb.total_len != int.from_bytes(data_len, byteorder=self.byte_order)):
            print("SHB block total length unmatch! : 0x%08x - 0x%08x" % (self.shb.total_len, int.from_bytes(data_len, byteorder=self.byte_order)))
            sys.exit("error")


    def read_next_block_type(self):
        data = self.file.read(BLOCK_TYPE_SIZE)
        block_type = int.from_bytes(data, byteorder=self.byte_order)
        if (len(data) != BLOCK_TYPE_SIZE):
            return EOF

        return block_type


    def read_next_block(self, type):
        data_len = self.file.read(BLOCK_LEN_SIZE)
        if (len(data_len) !=  BLOCK_LEN_SIZE):
            print("Invalid block structure!")
            sys.exit("error")

        total_len  = int.from_bytes(data_len, byteorder=self.byte_order)

        if (BLOCK_TYPE_IDB == type):
            block = cIDB(self, total_len)
            self.idbs.append(block)
        elif (BLOCK_TYPE_EPB == type):
            block = cEPB(self, total_len)
        else:
            block = cBlock(self, type, total_len)

        block.read_block()

        data_len = self.file.read(BLOCK_LEN_SIZE)
        if (len(data_len) !=  BLOCK_LEN_SIZE):
            print("Invalid block size! : 0x%08x" % (total_len))
            sys.exit("error")

        if (total_len != int.from_bytes(data_len, byteorder=self.byte_order)):
            print("block total length unmatch! : 0x%08x - 0x%08x" % (total_len, int.from_bytes(data_len, byteorder=self.byte_order)))
            sys.exit("error")

        block.disp_block()
        self.blocks.append(block)
        return

    def get_usb_device(self, bus_id, address):
        for usb in self.usb_devices:
            if ((usb.bus_id == bus_id) and (usb.address == address)):
                return usb

        usb = cUSBDevice(bus_id, address)
        self.usb_devices.append(usb)
        return usb


#####################################################
# pcapngファイル解析
#####################################################
def parse_file(file_path):
    global g_sections

    f = open(file_path, 'rb')
    data = f.read(BLOCK_TYPE_SIZE)
    block_type = int.from_bytes(data, byteorder='little')
    print("block_type : 0x%08x" % block_type)
    if (BLOCK_TYPE_SHB == block_type):
        while (True):
            section = cSection(f)
            section.read_shb()
            g_sections.append(section)
            while (True):
                block_type = section.read_next_block_type()
                if (EOF == block_type):
                    f.close()
                    return
                elif (BLOCK_TYPE_SHB == block_type):
                    break
                else:
                    section.read_next_block(block_type)

    else:
       print("Invalid first block type! block type : 0x%08x" % block_type)

    f.close()
    return


#####################################################
# USB関連パケットに関する表示
#####################################################
def check_usb_devices(section):
    for usb in section.usb_devices:
        print("usb device[%02x:%02x] VID:0x%04x, PID:0x%04x, with %d packets!" % (usb.bus_id, usb.address, usb.vid, usb.pid, len(usb.packets)))
        for config in usb.configs:
            print("    config[%d] num interfaces is %d, MaxPower:%d mA" % (config.ConfigurationValue, config.NumInterfaces, config.MaxPower * 2))
            for interface in config.Interfaces:
                print("        interface[%d] num endpoint is %d, Class:0x%02x" % (interface.InterfaceNumber, interface.NumEndpoints, interface.InterfaceClass))
                for endpoint in interface.Endpoints:
                    if (USB_ENDPOINT_ATTR_BULK == endpoint.mAttributes):
                        if (endpoint.EndpointAddress & 0x80):
                            print("            BULK IN  endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                        else:
                            print("            BULK OUT endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                    elif (USB_ENDPOINT_ATTR_INTR == endpoint.mAttributes):
                        print("            INTR IN  endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                    elif (USB_ENDPOINT_ATTR_ISOC == endpoint.mAttributes):
                        if (endpoint.EndpointAddress & 0x80):
                            print("            ISOC IN  endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                        else:
                            print("            ISOC OUT endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                    else:
                        print("            ???? ??? endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))


    return


#/*****************************************************************************/
#/* メイン関数                                                                */
#/*****************************************************************************/
def main():
    global g_sections

    argc = len(sys.argv)
    if (argc == 1):
        print("usage : pcapng_parse.py [target]")
        sys.exit(0)

    sys.argv.pop(0)
    for arg in sys.argv:
        if (os.path.isfile(arg)):
            parse_file(arg)
        else:
            print("%s is not valid file!" % arg)


    for section in g_sections:
        check_usb_devices(section)


if __name__ == "__main__":
    main()



