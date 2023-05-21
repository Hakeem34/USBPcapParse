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

USB_ENDPOINT_ATTR_MASK    = 0x03
USB_ENDPOINT_ATTR_CTRL    = 0x00
USB_ENDPOINT_ATTR_ISOC    = 0x01
USB_ENDPOINT_ATTR_BULK    = 0x02
USB_ENDPOINT_ATTR_INTR    = 0x03


#####################################################
# USBのCTRL転送に関する定義
#####################################################
USB_CTRL_REQTYP_BIT_DIRRECTION        = 0x80
USB_CTRL_REQTYP_BIT_HOST_TO_DEVICE    = 0x00
USB_CTRL_REQTYP_BIT_DEVICE_TO_HOST    = 0x80

USB_CTRL_REQTYP_BIT_REQ_TYPE          = 0x60
USB_CTRL_REQTYP_BIT_STANDARD_REQ      = 0x00
USB_CTRL_REQTYP_BIT_CLASS_REQ         = 0x20
USB_CTRL_REQTYP_BIT_VENDOR_REQ        = 0x40
USB_CTRL_REQTYP_BIT_RESERVED_REQ      = 0x60

USB_CTRL_REQTYP_BIT_REQ_TGT           = 0x1F
USB_CTRL_REQTYP_BIT_REQ_TGT_DEVICE    = 0x00
USB_CTRL_REQTYP_BIT_REQ_TGT_INTERFACE = 0x01
USB_CTRL_REQTYP_BIT_REQ_TGT_ENDPOINT  = 0x02
USB_CTRL_REQTYP_BIT_REQ_TGT_OTHER     = 0x03


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

USB_INTERFACE_CLASS_AUDIO               = 0x01
USB_INTERFACE_CLASS_CDC                 = 0x02
USB_INTERFACE_CLASS_HID                 = 0x03
USB_INTERFACE_CLASS_IMAGE               = 0x06
USB_INTERFACE_CLASS_PRINTER             = 0x07
USB_INTERFACE_CLASS_MSC                 = 0x08
USB_INTERFACE_CLASS_HUB                 = 0x09
USB_INTERFACE_CLASS_UVC                 = 0x0E
USB_INTERFACE_CLASS_WIRELESS_CONTROLLER = 0xE0
USB_INTERFACE_CLASS_VENDOR_SPECIFIC     = 0xFF

MIN_ENDPOINT_DESC_SIZE    = 7

#####################################################
# MTPに関する定義
#####################################################
MTP_CONTAINER_TYPE_UNKNOWN         = 0x0000
MTP_CONTAINER_TYPE_COMMAND         = 0x0001
MTP_CONTAINER_TYPE_DATA            = 0x0002
MTP_CONTAINER_TYPE_RESPONSE        = 0x0003
MTP_CONTAINER_TYPE_EVENT           = 0x0004

MTP_RES_OK                         = 0x2001
MTP_OP_NOT_SUPPORTED               = 0x2005

MTP_DATA_TYPE_UNDEF                = 0x0000
MTP_DATA_TYPE_INT8                 = 0x0001
MTP_DATA_TYPE_UINT8                = 0x0002
MTP_DATA_TYPE_INT16                = 0x0003
MTP_DATA_TYPE_UINT16               = 0x0004
MTP_DATA_TYPE_INT32                = 0x0005
MTP_DATA_TYPE_UINT32               = 0x0006
MTP_DATA_TYPE_INT64                = 0x0007
MTP_DATA_TYPE_UINT64               = 0x0008
MTP_DATA_TYPE_INT128               = 0x0009
MTP_DATA_TYPE_UINT128              = 0x000A
MTP_DATA_TYPE_ARRAY                = 0x4000
MTP_DATA_TYPE_STRING               = 0xFFFF

MTP_OPC_GET_DEVICE_INFO            = 0x1001
MTP_OPC_OPEN_SESSION               = 0x1002
MTP_OPC_CLOSE_SESSION              = 0x1003
MTP_OPC_GET_STORAGE_IDS            = 0x1004
MTP_OPC_GET_STORAGE_INFO           = 0x1005
MTP_OPC_GET_NUM_OBJECTS            = 0x1006
MTP_OPC_GET_OBJECT_HANDLES         = 0x1007
MTP_OPC_GET_OBJECT_INFO            = 0x1008
MTP_OPC_GET_OBJECT                 = 0x1009
MTP_OPC_GET_DEVICE_PROP_DESC       = 0x1014
MTP_OPC_GET_PARTIAL_OBJECT         = 0x101B
MTP_OPC_GET_OBJECT_PROPS_SUPPORTED = 0x9801
MTP_OPC_GET_OBJECT_PROPS_DESC      = 0x9802
MTP_OPC_GET_OBJECT_PROP_LIST       = 0x9805

OPC_TABLE = {
    MTP_OPC_GET_DEVICE_INFO            : "GetDeviceInfo",
    MTP_OPC_OPEN_SESSION               : "OpenSession",
    MTP_OPC_CLOSE_SESSION              : "CloseSession",
    MTP_OPC_GET_STORAGE_IDS            : "GetStorageIDs",
    MTP_OPC_GET_STORAGE_INFO           : "GetStorageInfo",
    MTP_OPC_GET_NUM_OBJECTS            : "GetNumObjects",
    MTP_OPC_GET_OBJECT_HANDLES         : "GetObjectHandles",
    MTP_OPC_GET_OBJECT_INFO            : "GetObjectInfo",
    MTP_OPC_GET_OBJECT                 : "GetObject",
    MTP_OPC_GET_DEVICE_PROP_DESC       : "GetDevicePropDesc",
    MTP_OPC_GET_PARTIAL_OBJECT         : "GetPartialObject",
    MTP_OPC_GET_OBJECT_PROPS_SUPPORTED : "GetObjectPropsSupported",
    MTP_OPC_GET_OBJECT_PROPS_DESC      : "GetObjectPropsDesc",
    MTP_OPC_GET_OBJECT_PROP_LIST       : "GetObjectPropList"
}

OBJ_FMT_TABLE = {
    0x3000            : "Undefined Object",
    0x3001            : "Association",
    0x3002            : "Script",
    0x3003            : "Executable",
    0x3004            : "Text",
    0x3005            : "HTML",
    0x3006            : "DPOF",
    0x3007            : "AIFF",
    0x3008            : "WAV",
    0x3009            : "MP3",
    0x300A            : "AVI",
    0x300B            : "MPEG",
    0x300C            : "ASF",
    0x3800            : "Undefined Image",
    0x3801            : "EXIF/JPEG",
    0x3802            : "TIFF/EP",
    0x3803            : "FlashPix",
    0x3804            : "BMP",
    0x3805            : "CIFF",
    0x3806            : "Reserved",
    0x3807            : "GIF",
    0x3808            : "JFIF",
    0x3809            : "CD",
    0x380A            : "PICT",
    0x380B            : "PNG",
    0x380C            : "Reserved",
    0x380D            : "TIFF",
    0x380E            : "TIFF/IT",
    0x380F            : "JP2",
    0x3810            : "JPX",
    0x3811            : "DNG",
    0x3812            : "HEIF",
    0xB802            : "Undefined Firmware",
    0xB881            : "WindowsImageFormat",
    0xB803            : "WBMP",
    0xB804            : "JPEG XR",
    0xB900            : "Undefined Audio",
    0xB901            : "WMA",
    0xB902            : "OGG",
    0xB903            : "ACC",
    0xB904            : "Audible",
    0xB906            : "FLAC",
    0xB907            : "QCELP",
    0xB908            : "AMR",
    0xB980            : "Undefined Video",
    0xB981            : "WMB",
    0xB982            : "MP4",
    0xB983            : "MP2",
    0xB984            : "3GP",
    0xB985            : "3G2",
    0xB986            : "AVCHD",
    0xB987            : "ATSC-TS",
    0xB988            : "DVB-TS",
    0xBA00            : "Undefined Collection",
    0xBA01            : "AbstractMultimediaAlbum",
    0xBA02            : "AbstractImageAlbum",
    0xBA03            : "AbstractAudioAlbum",
    0xBA04            : "AbstractVideoAlbum",
    0xBA05            : "AbstractAudio&VideoPlayList",
    0xBA06            : "AbstractContactGroup",
    0xBA07            : "AbstractMessageFolder",
    0xBA08            : "AbstractChapteredProduction",
    0xBA09            : "AbstractAudioPlayList",
    0xBA0A            : "AbstractVideoPlayList",
    0xBA0B            : "AbstractMediacast",
    0xBA10            : "WPL PlayList",
    0xBA11            : "M3U PlayList",
    0xBA14            : "PLS PlayList",
    0xBA80            : "Undefined Document",
    0xBA81            : "Abstract Document",
    0xBA82            : "XML Document",
#/* まだまだ続くが省略 */
}


EOF                       = -1


g_sections                = []



#####################################################
# USB MTP Object
#####################################################
class cMTP_Object:
    def __init__(self, parent):
        self.parent                 = parent           #cUSBInterfaceMTPクラスへの参照
        self.format_code            = 0
        self.props_supported        = []


#####################################################
# USB MTP Object Prop List Element
#####################################################
class cMTP_ObjectPropListElement:
    def __init__(self, parent):
        self.parent                 = parent           #cUSBInterfaceMTPクラスへの参照
        self.object_handle          = 0
        self.prop_code              = 0
        self.data_type              = 0
        self.value                  = 0


#####################################################
# USB MTP Object Property
#####################################################
class cMTP_Object_Prop:
    def __init__(self, parent):
        self.parent                 = parent           #cUSBInterfaceMTPクラスへの参照
        self.prop_code              = 0
        self.data_type              = 0
        self.get_set                = 0
        self.default_val            = ""
        self.group_code             = 0
        self.form_flag              = 0


#####################################################
# USB MTP Device Property
#####################################################
class cMTP_Device_Prop:
    def __init__(self, parent):
        self.parent                 = parent           #cUSBInterfaceMTPクラスへの参照
        self.prop_code              = 0
        self.data_type              = 0
        self.get_set                = 0
        self.factory_default_val    = ""
        self.current_val            = ""
        self.form_flag              = 0


#####################################################
# USB MTP Storage
#####################################################
class cMTP_Storage:
    def __init__(self, parent):
        self.parent                  = parent           #cUSBInterfaceMTPクラスへの参照
        self.storage_type            = 0
        self.file_system_type        = 0
        self.access_capability       = 0
        self.max_capacity            = 0
        self.free_space_in_bytes     = 0
        self.free_space_in_objects   = 0
        self.storage_description     = 0
        self.volume_identifier       = 0


#####################################################
# USB MTP Interface
#####################################################
class cUSBInterfaceMTP:
    def __init__(self, parent):
        self.parent                 = parent           #cUSBInterfaceクラスへの参照
        self.last_opc               = 0
        self.last_param             = 0
        self.standard_ver           = 0
        self.mtp_vendor_ex_id       = 0
        self.mtp_version            = 0
        self.mtp_extensions         = 0
        self.functional_mode        = 0
        self.operations_supported   = []
        self.events_supported       = []
        self.device_props_supported = []
        self.capture_formats        = []
        self.playback_formats       = []
        self.manufacturer           = ""
        self.model                  = ""
        self.device_ver             = ""
        self.serial_num             = ""
        self.objects                = []
        self.storages               = []
        self.device_props           = []
        self.object_prop_descs      = []
        self.object_props           = []


#####################################################
# USB Endpoint
#####################################################
class cUSBEndpoint:
    def __init__(self, parent, EndpointAddress):
        self.parent             = parent           #cUSBInterfaceクラスへの参照
        self.EndpointAddress    = EndpointAddress
        self.mAttributes        = 0
        self.MaxPacketSize      = 0
        self.Interval           = 0


#####################################################
# USB Interface
#####################################################
class cUSBInterface:
    def __init__(self, parent, InterfaceNumber):
        self.parent             = parent           #cUSBConfigクラスへの参照
        self.InterfaceNumber    = InterfaceNumber
        self.NumEndpoints       = 0
        self.InterfaceClass     = 0
        self.InterfaceSubClass  = 0
        self.InterfaceProtocol  = 0
        self.Endpoints          = []
        self.Child              = None

    def get_usb_endpoint(self, EndpointAddress):
        for endpoint in self.Endpoints:
            if (endpoint.EndpointAddress == EndpointAddress):
                return endpoint

        endpoint = cUSBEndpoint(self, EndpointAddress)
        self.Endpoints.append(endpoint)
        return endpoint

    def is_owned_endpoint(self, EndpointAddress):
        for endpoint in self.Endpoints:
            if (endpoint.EndpointAddress == EndpointAddress):
                return True

        return False

    def create_child(self):
        if (USB_INTERFACE_CLASS_IMAGE == self.InterfaceClass):
            self.child = cUSBInterfaceMTP(self)



#####################################################
# USB Config
#####################################################
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

    def get_interface_by_endpoint(self, Endpoint):
        for interface in self.Interfaces:
            if (interface.is_owned_endpoint(Endpoint)):
                return interface

        return None

#####################################################
# USB Device
#####################################################
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
        self.set_config        = -1

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

    def get_interface_by_endpoint(self, Endpoint):
        if (self.set_config == -1):
            return None

        config = self.get_usb_config(self.set_config)
        return config.get_interface_by_endpoint(Endpoint)


#####################################################
# USB MTP Generic Container Dataset
#####################################################
class cUSBContainer:
    def __init__(self, parent):
        self.parent        = parent           #cUSBPcapHeaderクラスへの参照
        self.length        = 0
        self.type          = 0
        self.code          = 0
        self.transactionID = 0


    def read_data_with_type(self, data_type, list):

        if (data_type == MTP_DATA_TYPE_STRING):
            string = self.parent.read_header_string()
            print("MTP PropList[%d]       data(string) : %s" % (list, string))
            return 
        elif (data_type >= MTP_DATA_TYPE_ARRAY):
            is_array = True
            data_type = data_type & 0xFF
        else:
            is_array = False

        if   ((MTP_DATA_TYPE_INT8  == data_type) or (MTP_DATA_TYPE_UINT8  == data_type)):
            data_size = 1
        elif ((MTP_DATA_TYPE_INT16 == data_type) or (MTP_DATA_TYPE_UINT16 == data_type)):
            data_size = 2
        elif ((MTP_DATA_TYPE_INT32 == data_type) or (MTP_DATA_TYPE_UINT32 == data_type)):
            data_size = 4
        elif ((MTP_DATA_TYPE_INT64 == data_type) or (MTP_DATA_TYPE_UINT64 == data_type)):
            data_size = 8
        elif ((MTP_DATA_TYPE_INT128 == data_type) or (MTP_DATA_TYPE_UINT128 == data_type)):
            data_size = 16

        if (is_array):
            array_size = self.parent.read_header_element(4)
            array = []
            while(array_size > 0):
                data = self.parent.read_header_element(data_size)
                print("MTP PropList[%d]       data(array) : 0x%08x" % (list, data))
                array.append(data)
                array_size -= 1

            return array
        else:
            data = self.parent.read_header_element(data_size)
            print("MTP PropList[%d]       data(numeric) : 0x%08x" % (list, data))
            return data

        return 0

    def read_get_device_props_desc_data(self, usb, interface):
        parent = self.parent
        mtp = interface.child
        device_prop                     = cMTP_Device_Prop(mtp)
        device_prop.prop_code           = parent.read_header_element(2)
        device_prop.data_type           = parent.read_header_element(2)
        device_prop.get_set             = parent.read_header_element(1)
        device_prop.factory_default_val = parent.read_header_string()
        device_prop.current_val         = parent.read_header_string()
        device_prop.form_flag           = parent.read_header_element(1)
        print("MTP            Prop Code           : 0x%04x" % device_prop.prop_code)
        print("MTP            Data Type           : 0x%04x" % device_prop.data_type)
        print("MTP            Get/Set             : 0x%02x" % device_prop.get_set)
        print("MTP            Factory Default Val : %s" % device_prop.factory_default_val)
        print("MTP            Current Val         : %s" % device_prop.current_val)
        print("MTP            Form Flag           : 0x%02x" % device_prop.form_flag)
        mtp.device_props.append(device_prop)
        return

    def read_get_object_prop_list(self, usb, interface):
        parent = self.parent
        mtp = interface.child
        object_handle    = interface.child.last_param
        object_prop_code = interface.child.last_param2

        number_of_element = parent.read_header_element(4)
        list = 0
        while (list < number_of_element):
            object_prop = cMTP_ObjectPropListElement(mtp)
            object_prop.object_handle = parent.read_header_element(4)
            object_prop.prop_code     = parent.read_header_element(2)
            object_prop.data_type     = parent.read_header_element(2)
            print("MTP PropList[%d]       object_handle : 0x%08x" % (list, object_prop.object_handle))
            print("MTP PropList[%d]       prop_code     : 0x%04x" % (list, object_prop.prop_code))
            print("MTP PropList[%d]       data_type     : 0x%04x" % (list, object_prop.data_type))
            self.read_data_with_type(object_prop.data_type, list)
            mtp.object_props.append(object_prop)
            list += 1
        return

    def read_get_object_props_desc(self, usb, interface):
        parent = self.parent
        mtp = interface.child
        object_prop_code   = mtp.last_param
        object_format_code = mtp.last_param2

        object_prop                     = cMTP_Object_Prop(mtp)
        object_prop.prop_code           = parent.read_header_element(2)
        object_prop.data_type           = parent.read_header_element(2)
        object_prop.get_set             = parent.read_header_element(1)

        if (object_prop.data_type   == 0x0002) or (object_prop.data_type == 0x0001):
            object_prop.default_val         = parent.read_header_element(1)
        elif (object_prop.data_type == 0x0004) or (object_prop.data_type == 0x0003):
            object_prop.default_val         = parent.read_header_element(2)
        elif (object_prop.data_type == 0x0006) or (object_prop.data_type == 0x0005):
            object_prop.default_val         = parent.read_header_element(4)
        elif (object_prop.data_type == 0x0008) or (object_prop.data_type == 0x0007):
            object_prop.default_val         = parent.read_header_element(8)
        elif (object_prop.data_type == 0x000A) or (object_prop.data_type == 0x0009):
            object_prop.default_val         = parent.read_header_element(16)
        elif (object_prop.data_type == 0xFFFF):
            object_prop.default_val         = parent.read_header_string()
        elif (object_prop.data_type >= 0x4000):
            #/* Array型の場合、必ず32bitの0となる */
            object_prop.default_val         = parent.read_header_element(4)
        else:
            object_prop.default_val         = parent.read_header_element(4)

        object_prop.group_code          = parent.read_header_element(4)
        object_prop.form_flag           = parent.read_header_element(1)
        if (OBJ_FMT_TABLE.get(object_format_code)):
            print("MTP Get Object Prop for %s(0x%x)" % (OBJ_FMT_TABLE.get(object_format_code), object_format_code))
        else:
            print("MTP Get Object Prop for Unknown Format(0x%x)" % object_format_code)

        print("MTP            Prop Code           : 0x%04x" % object_prop.prop_code)
        print("MTP            Data Type           : 0x%04x" % object_prop.data_type)
        print("MTP            Get/Set             : 0x%02x" % object_prop.get_set)
        if (object_prop.data_type < 0x4000):
            print("MTP            Default Val         : 0x%02x" % object_prop.default_val)
        else:
            print("MTP            Default Val         : %s" % object_prop.default_val)
        print("MTP            Group Code          : 0x%08x" % object_prop.group_code)
        print("MTP            Form Flag           : 0x%02x" % object_prop.form_flag)
        mtp.object_prop_descs.append(object_prop)
        return

    def read_get_object_handles(self, usb, interface):
        parent = self.parent
        mtp = interface.child
        handle_num = parent.read_header_element(4)
        print("MTP            Handle num        : 0x%04x" % handle_num)
        while (handle_num > 0):
            handle = parent.read_header_element(4)
            handle_num -= 1
            print("MTP            handle            : 0x%08x" % handle)

        return


    def read_get_storage_info(self, usb, interface):
        parent = self.parent
        mtp = interface.child
        storage = cMTP_Storage(mtp)
        storage.storage_type          = parent.read_header_element(2)
        storage.file_system_type      = parent.read_header_element(2)
        storage.access_capability     = parent.read_header_element(2)
        storage.max_capacity          = parent.read_header_element(8)
        storage.free_space_in_bytes   = parent.read_header_element(8)
        storage.free_space_in_objects = parent.read_header_element(4)
        storage.storage_description   = parent.read_header_string()
        storage.volume_identifier     = parent.read_header_string()
        mtp.storages.append(storage)
        print("MTP            Storage Type        : 0x%04x" % storage.storage_type)
        print("MTP            FileSystem Type     : 0x%04x" % storage.file_system_type)
        print("MTP            Access Capability   : 0x%04x" % storage.access_capability)
        print("MTP            Max Capacity        : 0x%x" % storage.max_capacity)
        print("MTP            Free Space in Bytes : 0x%x" % storage.free_space_in_bytes)
        print("MTP            Free Space in Objs  : 0x%x" % storage.free_space_in_objects)
        print("MTP            Storage Description : %s" % storage.storage_description)
        print("MTP            Volume Identifier   : %s" % storage.volume_identifier)
        return

    def read_get_storage_ids(self, usb, interface):
        parent = self.parent
        mtp = interface.child

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            storage_id = parent.read_header_element(4)
            list_size -= 1
            print("MTP            StorageID : 0x%08x" % storage_id)
        return


    def read_get_object_props_supported_data(self, usb, interface):
        parent = self.parent
        mtp = interface.child
        object = cMTP_Object(mtp)
        object.format_code = mtp.last_param

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            prop = parent.read_header_element(2)
            object.props_supported.append(prop)
            list_size -= 1
            print("MTP            ObjectProps supported : 0x%04x" % prop)

        mtp.objects.append(object)
        return

    def read_get_device_info_data(self, usb, interface):
        parent = self.parent
        mtp = interface.child

        mtp.standard_ver     = parent.read_header_element(2)
        mtp.mtp_vendor_ex_id = parent.read_header_element(4)
        mtp.mtp_version      = parent.read_header_element(2)
        mtp.mtp_extensions   = parent.read_header_string()
        mtp.functional_mode  = parent.read_header_element(2)

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            opc = parent.read_header_element(2)
            mtp.operations_supported.append(opc)
            list_size -= 1
            print("MTP            OPC supported : 0x%04x" % opc)

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            event = parent.read_header_element(2)
            mtp.events_supported.append(event)
            list_size -= 1
            print("MTP            EVENT supported : 0x%04x" % event)

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            prop = parent.read_header_element(2)
            mtp.device_props_supported.append(prop)
            list_size -= 1
            print("MTP            DEVICE PROPS supported : 0x%04x" % prop)

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            format = parent.read_header_element(2)
            mtp.capture_formats.append(format)
            list_size -= 1
            print("MTP            Capture Format : 0x%04x" % format)

        list_size            = parent.read_header_element(4)
        while (list_size > 0):
            format = parent.read_header_element(2)
            mtp.playback_formats.append(format)
            list_size -= 1
            print("MTP            PlayBack Format : 0x%04x" % format)


        mtp.manufacturer   = parent.read_header_string()
        mtp.model          = parent.read_header_string()
        mtp.device_ver     = parent.read_header_string()
        mtp.serial_num     = parent.read_header_string()
        print("MTP            Manufacturer   : %s" % mtp.manufacturer)
        print("MTP            Model          : %s" % mtp.model)
        print("MTP            Device Version : %s" % mtp.device_ver)
        print("MTP            Serial Number  : %s" % mtp.serial_num)
        return


    def read_mtp_bulk_out(self, usb, interface):
        parent = self.parent

        if (OPC_TABLE.get(self.code)):
            opc = OPC_TABLE[self.code]
            if (MTP_OPC_OPEN_SESSION == self.code):
                session_id = parent.read_header_element(4)
                print("MTP[0x%08x]OpenSession(0x%04x), SessionID : 0x%08x" % (self.transactionID, self.code, session_id))
            elif (MTP_OPC_GET_DEVICE_INFO == self.code):
                print("MTP[0x%08x]GetDeviceInfo(0x%04x)" % (self.transactionID, self.code))
            elif (MTP_OPC_GET_DEVICE_PROP_DESC == self.code):
                device_prop_code = parent.read_header_element(4)
                interface.child.last_param = device_prop_code
                print("MTP[0x%08x]GetDevicePropDesc(0x%04x), DevicePropCode : 0x%04x" % (self.transactionID, self.code, device_prop_code))
            elif (MTP_OPC_GET_OBJECT_PROPS_SUPPORTED == self.code):
                object_fc = parent.read_header_element(4)
                interface.child.last_param = object_fc
                print("MTP[0x%08x]GetObjectPropsSupported(0x%04x), ObjectFormatCode : 0x%04x" % (self.transactionID, self.code, object_fc))
            elif (MTP_OPC_GET_OBJECT_PROPS_DESC == self.code):
                object_prop_code   = parent.read_header_element(4)
                object_format_code = parent.read_header_element(4)
                interface.child.last_param  = object_prop_code
                interface.child.last_param2 = object_format_code
                print("MTP[0x%08x]GetObjectPropsDesc(0x%04x), ObjectPropCode : 0x%04x, ObjectFormatCode : 0x%04x" % (self.transactionID, self.code, object_prop_code, object_format_code))
            elif (MTP_OPC_GET_OBJECT_PROP_LIST == self.code):
                object_handle      = parent.read_header_element(4)
                object_format_code = parent.read_header_element(4)
                object_prop_code   = parent.read_header_element(4)
                interface.child.last_param  = object_handle
                interface.child.last_param2 = object_prop_code
                print("MTP[0x%08x]GetObjectPropsList(0x%04x), Handle:0x%08x, FormatCode : 0x%04x, PropCode : 0x%04x" % (self.transactionID, self.code, object_handle, object_format_code, object_prop_code))
            elif (MTP_OPC_GET_STORAGE_IDS == self.code):
                print("MTP[0x%08x]GetStorageIDs(0x%04x)" % (self.transactionID, self.code))
            elif (MTP_OPC_GET_STORAGE_INFO == self.code):
                storage_id = parent.read_header_element(4)
                interface.child.last_param = storage_id
                print("MTP[0x%08x]GetStorageInfo(0x%04x) storage_id : %d" % (self.transactionID, self.code, storage_id))
            elif (MTP_OPC_GET_OBJECT_HANDLES == self.code):
                storage_id         = parent.read_header_element(4)
                object_format_code = parent.read_header_element(4)
                handle_association = parent.read_header_element(4)
                print("MTP[0x%08x]GetObjectHandles(0x%04x) storage_id : 0x%08x, format_code : 0x%04x, handle_association : 0x%08x" % (self.transactionID, self.code, storage_id, object_format_code, handle_association))
            else:
                print("BULK OUT to Imaging, packet_len : %d, %s(0x%04x)" % (parent.packet_len, opc, self.code))
            
        else:
            print("BULK OUT to Imaging, packet_len : %d, UNKNOWN OPC(0x%04x)" % (parent.packet_len, self.code))
        return

    def read_mtp_bulk_in(self, usb, interface):
        parent = self.parent

        if (MTP_RES_OK == self.code):
            print("MTP[0x%08x]Response OK(0x%04x)" % (self.transactionID, self.code))
        elif (MTP_OPC_GET_DEVICE_INFO == self.code):
            print("MTP[0x%08x]GetDeviceInfo(0x%04x) data" % (self.transactionID, self.code))
            self.read_get_device_info_data(usb, interface)
        elif (MTP_OPC_GET_OBJECT_PROPS_SUPPORTED == self.code):
            print("MTP[0x%08x]GetObjectPropsSupported(0x%04x) data for Format:0x%04x" % (self.transactionID, self.code, interface.child.last_param))
            self.read_get_object_props_supported_data(usb, interface)
        elif (MTP_OPC_GET_DEVICE_PROP_DESC == self.code):
            print("MTP[0x%08x]GetDevicePropDesc(0x%04x) data for DevicePropCode : 0x%04x" % (self.transactionID, self.code, interface.child.last_param))
            self.read_get_device_props_desc_data(usb, interface)
        elif (MTP_OPC_GET_STORAGE_IDS == self.code):
            print("MTP[0x%08x]GetStorageIDs(0x%04x) data" % (self.transactionID, self.code))
            self.read_get_storage_ids(usb, interface)
        elif (MTP_OPC_GET_STORAGE_INFO == self.code):
            print("MTP[0x%08x]GetStorageInfo(0x%04x) data" % (self.transactionID, self.code))
            self.read_get_storage_info(usb, interface)
        elif (MTP_OPC_GET_OBJECT_HANDLES == self.code):
            print("MTP[0x%08x]GetObjectHandles(0x%04x) data" % (self.transactionID, self.code))
            self.read_get_object_handles(usb, interface)
        elif (MTP_OPC_GET_OBJECT_PROPS_DESC == self.code):
            print("MTP[0x%08x]GetObjectPropsDesc(0x%04x) data" % (self.transactionID, self.code))
            self.read_get_object_props_desc(usb, interface)
        elif (MTP_OPC_GET_OBJECT_PROP_LIST == self.code):
            print("MTP[0x%08x]GetObjectPropsList(0x%04x) data" % (self.transactionID, self.code))
            self.read_get_object_prop_list(usb, interface)
        else:
            print("BULK IN from Imaging, packet_len : %d, code : 0x%04x" % (parent.packet_len, self.code))
        return



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
        self.container    = None

    def read_header_element(self, size):
        parent = self.parent
        grandpa = parent.parent

        tmp_data = grandpa.file.read(size)
#       print("tmp_data[%02d:%02d] : " % (self.bytes_read, size), tmp_data)
        self.bytes_read += size
        return int.from_bytes(tmp_data, byteorder=grandpa.byte_order)

    def read_header_string(self):
        string = ""

        parent = self.parent
        grandpa = parent.parent

        tmp_data = grandpa.file.read(1)
        self.bytes_read += 1
        string_length = int.from_bytes(tmp_data, byteorder=grandpa.byte_order)
        while(string_length > 0):
            tmp_data = grandpa.file.read(2)
            self.bytes_read += 2
            code = int.from_bytes(tmp_data, byteorder=grandpa.byte_order)
            if (0x0000 == code):
                break;

            string += tmp_data.decode('UTF-16')
            string_length -= 1

        return string


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
        if (remain >= bytes_to_go + start_bytes_read):
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
                    interface.create_child()

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

    def read_mtp_bulk_out(self, usb, interface):
        if (self.packet_len > 0):
            container                = cUSBContainer(self)
            container.length         = self.read_header_element(4)
            container.type           = self.read_header_element(2)
            container.code           = self.read_header_element(2)
            container.transactionID  = self.read_header_element(4)
            interface.child.last_opc = container.code
            self.container           = container
            container.read_mtp_bulk_out(usb, interface)
        else:
            print("BULK OUT to Imaging without data!")


    def read_mtp_bulk_in(self, usb, interface):
        if (self.packet_len > 0):
            container               = cUSBContainer(self)
            container.length        = self.read_header_element(4)
            container.type          = self.read_header_element(2)
            container.code          = self.read_header_element(2)
            container.transactionID = self.read_header_element(4)
            self.container = container
            container.read_mtp_bulk_in(usb, interface)
        else:
            print("BULK IN from Imaging without data!")

    def read_bulk_out_data(self, usb):
        interface = usb.get_interface_by_endpoint(self.endpoint)
        if (USB_INTERFACE_CLASS_IMAGE == interface.InterfaceClass):
            self.read_mtp_bulk_out(usb, interface)
        return

    def read_bulk_in_data(self, usb):
        interface = usb.get_interface_by_endpoint(self.endpoint)
        if (USB_INTERFACE_CLASS_IMAGE == interface.InterfaceClass):
            self.read_mtp_bulk_in(usb, interface)
        return

    def is_standard_get_request_type(self, mRequestType):
        if ((USB_CTRL_REQTYP_BIT_DIRRECTION & mRequestType) == USB_CTRL_REQTYP_BIT_DEVICE_TO_HOST):
            if ((USB_CTRL_REQTYP_BIT_REQ_TYPE & mRequestType) == USB_CTRL_REQTYP_BIT_STANDARD_REQ):
                return True

        return False

    def is_standard_set_request_type(self, mRequestType):
        if ((USB_CTRL_REQTYP_BIT_DIRRECTION & mRequestType) == USB_CTRL_REQTYP_BIT_HOST_TO_DEVICE):
            if ((USB_CTRL_REQTYP_BIT_REQ_TYPE & mRequestType) == USB_CTRL_REQTYP_BIT_STANDARD_REQ):
                return True

        return False


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

                if (self.is_standard_get_request_type(self.mRequestType)):
                    if (USB_CTRL_REQ_GET_DESC == self.Request):
                        self.DescIndex = self.read_header_element(1)
                        self.DescType  = self.read_header_element(1)
                    if (USB_CTRL_REQ_GET_ST == self.Request):
                        self.Value  = self.read_header_element(2)
                        self.Index  = self.read_header_element(2)
                        self.Length = self.read_header_element(2)

                elif (self.is_standard_set_request_type(self.mRequestType)):
                    if (USB_CTRL_REQ_SET_CFG == self.Request):
                        self.ConfigValue = self.read_header_element(1)
                        usb.set_config = self.ConfigValue
            else:
                if (last.trans_type == USB_TRANS_TYPE_CTRL):
                    if (last.is_standard_get_request_type(last.mRequestType)):
                        if (USB_CTRL_REQ_GET_DESC == last.Request):
                            self.read_get_desc_res(remain, usb, last)
                        elif (USB_CTRL_REQ_GET_ST == last.Request):
                            self.Status  = self.read_header_element(2)
        elif (self.trans_type == USB_TRANS_TYPE_BULK):
            if (self.irp_info == 0):
                self.read_bulk_out_data(usb)
            else:
                self.read_bulk_in_data(usb)



        if (remain < self.bytes_read):
            print("Invalid block read @0x%08x" % self.parent.parent.file.tell())
            sys.exit("error")

        self.data = self.parent.parent.file.read(remain - self.bytes_read)

        usb.add_packet(self)
        return

    def disp_packet(self):
        parent = self.parent
        ts_l = (((parent.time_stamp_h << 32) + parent.time_stamp_l) - parent.parent.first_ts) % 1000000
        ts_h = (((parent.time_stamp_h << 32) + parent.time_stamp_l) - parent.parent.first_ts) / 1000000
        print("read EPB(USBPcap) @ 0x%08x, block! length : %3d, Interface : %d, TS[%08x-%08x](%d.%06d)" % (parent.position, parent.total_len, parent.interface_id, parent.time_stamp_h, parent.time_stamp_l, ts_h, ts_l))

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
    def __init__(self, parent, length, position):
        self.block_type  = BLOCK_TYPE_IDB
        self.total_len   = length
        self.link_type   = 0
        self.snap_len    = 0
        self.parent      = parent           #cSectionクラスへの参照
        self.position     = position

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
    def __init__(self, parent, length, position):
        self.block_type   = BLOCK_TYPE_EPB
        self.total_len    = length
        self.interface_id = 0
        self.time_stamp_h = 0
        self.time_stamp_l = 0
        self.capture_len  = 0
        self.packet_len   = 0
        self.parent       = parent           #cSectionクラスへの参照
        self.child        = ""
        self.position     = position

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

        if (self.parent.first_ts == 0):
            self.parent.first_ts = (self.time_stamp_h << 32) + self.time_stamp_l

        return

    def disp_block(self):
         self.child.disp_packet()


#####################################################
# Any other blocks
#####################################################
class cBlock:
    def __init__(self, parent, type, length, position):
        self.block_type   = type
        self.total_len    = length
        self.parent       = parent           #cSectionクラスへの参照
        self.position     = position

    def read_block(self):
        data_waste = self.parent.file.read(self.total_len - BLOCK_TYPE_SIZE - BLOCK_LEN_SIZE - BLOCK_LEN_SIZE)
        return

    def disp_block(self):
        print("read block @ 0x%08x, type : 0x%08x, length : %d" % (self.position, self.block_type, self.total_len))


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
        self.first_ts    = 0

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


    def read_next_block(self, type, position):
        data_len = self.file.read(BLOCK_LEN_SIZE)
        if (len(data_len) !=  BLOCK_LEN_SIZE):
            print("Invalid block structure!")
            sys.exit("error")

        total_len  = int.from_bytes(data_len, byteorder=self.byte_order)

        if (BLOCK_TYPE_IDB == type):
            block = cIDB(self, total_len, position)
            self.idbs.append(block)
        elif (BLOCK_TYPE_EPB == type):
            block = cEPB(self, total_len, position)
        else:
            block = cBlock(self, type, total_len, position)

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
                position = f.tell()
                block_type = section.read_next_block_type()
                if (EOF == block_type):
                    f.close()
                    return
                elif (BLOCK_TYPE_SHB == block_type):
                    print("new SHB @ 0x%08x" % position)
                    break
                else:
                    section.read_next_block(block_type, position)

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
                    if (USB_ENDPOINT_ATTR_BULK == (USB_ENDPOINT_ATTR_MASK & endpoint.mAttributes)):
                        if (endpoint.EndpointAddress & 0x80):
                            print("            BULK IN  endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                        else:
                            print("            BULK OUT endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                    elif (USB_ENDPOINT_ATTR_INTR == (USB_ENDPOINT_ATTR_MASK & endpoint.mAttributes)):
                        print("            INTR IN  endpoint[0x%02x] Attr:0x%x, MaxPacketSize:0x%x, Interval:%d" % (endpoint.EndpointAddress, endpoint.mAttributes, endpoint.MaxPacketSize, endpoint.Interval))
                    elif (USB_ENDPOINT_ATTR_ISOC == (USB_ENDPOINT_ATTR_MASK & endpoint.mAttributes)):
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



