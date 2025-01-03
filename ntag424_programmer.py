import ctypes
from ctypes import *
import sys
import platform
import os
import time
import card_types
from datetime import datetime
##########################################################################
# uFCODER - LOAD LIBRARY
##########################################################################

print("sys.platform = " + sys.platform)
if sys.platform.startswith('win'):
    import msvcrt
    from ctypes import windll
    # Used for specifying lib for OS version, 32/64bit
    if platform.architecture()[0] == '32bit':
        uFR = ctypes.windll.LoadLibrary(
            "ufr-lib//windows//x86//uFCoder-x86.dll")
    elif platform.architecture()[0] == '64bit':
        uFR = ctypes.windll.LoadLibrary(
            "ufr-lib//windows//x86_64//uFCoder-x86_64.dll")
elif sys.platform.startswith('linux'):
    # used for specifying lib for OS version, 32/64bit
    if os.uname()[4][:3] == 'arm':
        uFR = cdll.LoadLibrary("ufr-lib//linux//arm-hf//libuFCoder-armhf.so")
    elif platform.architecture()[0] == '32bit':
        uFR = cdll.LoadLibrary("ufr-lib//linux//x86//libuFCoder-x86.so")
    elif platform.architecture()[0] == '64bit':
        uFR = cdll.LoadLibrary("ufr-lib//linux//x86_64//libuFCoder-x86_64.so")
elif sys.platform.startswith('darwin'):
    uFR = cdll.LoadLibrary("ufr-lib//macos//x86_64//libuFCoder-x86_64.dylib")
else:
    print("Platform not recognized? os.uname = " + os.uname)

##########################################################################
# uFCODER API - IMPORT FUNCTIONS
##########################################################################

def ReaderOpenEx(reader_type, port_name, port_interface, arg):
    openReader = uFR.ReaderOpenEx
    openReader.argtypes = (c_uint32, c_char_p, c_uint32, c_char_p)
    openReader.restype = c_uint
    b = c_char_p(port_name.encode('utf-8'))
    c = c_char_p(arg.encode('utf-8'))

    return openReader(reader_type, b, port_interface, c)

##########################################################################

def ReaderOpen():
    openReader = uFR.ReaderOpen

    return openReader()

##########################################################################

def ReaderUISignal(light, sound):
    uiSignal = uFR.ReaderUISignal
    uiSignal.argtypes = (c_ubyte, c_ubyte)
    uiSignal.restype = c_uint
    uiSignal(light, sound)

##########################################################################

def ReaderClose():
    func = uFR.ReaderClose

    return func()

###########################f###############################################

def GetCardIdEx(sak, uid, uid_size):
    getCardIdEx = uFR.GetCardIdEx
    getCardIdEx.argtypes = [ POINTER(c_ubyte), (c_ubyte * 11), POINTER(c_ubyte)]
    getCardIdEx.restype = c_uint

    return getCardIdEx(byref(sak), uid, byref(uid_size))

##########################################################################

def GetDlogicCardType(card_type):
    getCardType = uFR.GetDlogicCardType
    getCardType.argtypes = [ POINTER(c_ubyte)]
    getCardType.restype = c_uint

    return getCardType(byref(card_type))

##########################################################################
##########################################################################

def nt4h_set_global_parameters(file_no, key_no, communication_mode):

    nt4h_set_global_parametersFunc = uFR.nt4h_set_global_parameters
    nt4h_set_global_parametersFunc.argtypes = [
    c_ubyte,  # file_no (uint8_t)
    c_ubyte,  # key_no (uint8_t)
    c_ubyte   # communication_mode (uint8_t)
    ]

    nt4h_set_global_parameters.restype = c_uint

    return nt4h_set_global_parametersFunc(file_no, key_no, communication_mode)
##########################################################################
def nt4h_change_sdm_file_settings_pk(aes_key_ext, file_no, key_no, curr_communication_mode, new_communication_mode, 
                                    read_key_no, write_key_no, read_write_key_no, change_key_no,
                                    uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
                                    meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
                                    uid_offset, read_ctr_offset, picc_data_offset, mac_input_offset,
                                    enc_offset, enc_length, mac_offset, read_ctr_limit):

    nt4h_change_sdm_file_settings_pkFunc = uFR.nt4h_change_sdm_file_settings_pk
    nt4h_change_sdm_file_settings_pkFunc.argtypes = [
        ctypes.POINTER(c_ubyte),   # uint8_t *aes_key_ext
        c_ubyte,                  # uint8_t file_no
        c_ubyte,                  # uint8_t key_no
        c_ubyte,                  # uint8_t curr_communication_mode
        c_ubyte,                  # uint8_t new_communication_mode

        c_ubyte,                  # uint8_t read_key_no
        c_ubyte,                  # uint8_t write_key_no
        c_ubyte,                  # uint8_t read_write_key_no
        c_ubyte,                  # uint8_t change_key_no

        c_ubyte,                  # uint8_t uid_enable
        c_ubyte,                  # uint8_t read_ctr_enable
        c_ubyte,                  # uint8_t read_ctr_limit_enable
        c_ubyte,                  # uint8_t enc_file_data_enable

        c_ubyte,                  # uint8_t meta_data_key_no
        c_ubyte,                  # uint8_t file_data_read_key_no
        c_ubyte,                  # uint8_t read_ctr_key_no

        c_uint,                   # uint8_t uid_offset
        c_uint,                   # uint8_t read_ctr_offset
        c_uint,                   # uint8_t picc_data_offset
        c_uint,                   # uint8_t mac_input_offset

        c_uint,                   # uint8_t enc_offset
        c_uint,                   # uint8_t enc_length
        c_uint,                   # uint8_t mac_offset
        c_uint,                   # uint8_t read_ctr_limit
    ]
    nt4h_change_sdm_file_settings_pkFunc.restype = c_uint

    return nt4h_change_sdm_file_settings_pkFunc(aes_key_ext, file_no, key_no, curr_communication_mode, new_communication_mode, 
                                    read_key_no, write_key_no, read_write_key_no, change_key_no,
                                    uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
                                    meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
                                    uid_offset, read_ctr_offset, picc_data_offset, mac_input_offset,
                                    enc_offset, enc_length, mac_offset, read_ctr_limit)

##########################################################################

def nt4h_tt_change_sdm_file_settings_pk(aes_key_ext, file_no, key_no, curr_communication_mode, new_communication_mode, 
                                    read_key_no, write_key_no, read_write_key_no, change_key_no,
                                    uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
                                    meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
                                    uid_offset, read_ctr_offset, picc_data_offset, mac_input_offset,
                                    enc_offset, enc_length, mac_offset, read_ctr_limit,
                                    tt_status_enable, tt_status_offset):

    nt4h_tt_change_sdm_file_settings_pkFunc = uFR.nt4h_tt_change_sdm_file_settings_pk
    nt4h_tt_change_sdm_file_settings_pkFunc.argtypes = [
        ctypes.POINTER(c_ubyte),  # uint8_t *aes_key_ext
        c_ubyte,                  # uint8_t file_no
        c_ubyte,                  # uint8_t key_no
        c_ubyte,                  # uint8_t curr_communication_mode
        c_ubyte,                  # uint8_t new_communication_mode

        c_ubyte,                  # uint8_t read_key_no
        c_ubyte,                  # uint8_t write_key_no
        c_ubyte,                  # uint8_t read_write_key_no
        c_ubyte,                  # uint8_t change_key_no

        c_ubyte,                  # uint8_t uid_enable
        c_ubyte,                  # uint8_t read_ctr_enable
        c_ubyte,                  # uint8_t read_ctr_limit_enable
        c_ubyte,                  # uint8_t enc_file_data_enable

        c_ubyte,                  # uint8_t meta_data_key_no
        c_ubyte,                  # uint8_t file_data_read_key_no
        c_ubyte,                  # uint8_t read_ctr_key_no

        c_uint,                   # uint8_t uid_offset
        c_uint,                   # uint8_t read_ctr_offset
        c_uint,                   # uint8_t picc_data_offset
        c_uint,                   # uint8_t mac_input_offset

        c_uint,                   # uint8_t enc_offset
        c_uint,                   # uint8_t enc_length
        c_uint,                   # uint8_t mac_offset
        c_uint,                   # uint8_t read_ctr_limit

        c_ubyte,                   # uint8_t tt_status_enable
        c_uint,                   # uint8_t tt_status_offset
    ]
    nt4h_tt_change_sdm_file_settings_pkFunc.restype = c_uint

    return nt4h_tt_change_sdm_file_settings_pkFunc(aes_key_ext, file_no, key_no, curr_communication_mode, new_communication_mode, 
                                    read_key_no, write_key_no, read_write_key_no, change_key_no,
                                    uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
                                    meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
                                    uid_offset, read_ctr_offset, picc_data_offset, mac_input_offset,
                                    enc_offset, enc_length, mac_offset, read_ctr_limit,
                                    tt_status_enable, tt_status_offset)

##########################################################################

def nt4h_tt_get_file_settings(file_no, file_type, comm_mode, sdm_enable, file_size,
    read_key_no, write_key_no, read_write_key_no, change_key_no,
    uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
    meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
    uid_offset, read_ctr_offset, picc_data_offset,
    mac_input_offset, enc_offset, enc_length, mac_offset, read_ctr_limit,
    tt_status_enable, tt_status_offset):
    
    nt4h_tt_get_file_settingsFunc = uFR.nt4h_tt_get_file_settings
    nt4h_tt_get_file_settingsFunc.argtypes = [
        c_ubyte,                  # uint8_t file_no

        ctypes.POINTER(c_ubyte),  # uint8_t file_type
        ctypes.POINTER(c_ubyte),  # uint8_t communication_mode
        ctypes.POINTER(c_ubyte),  # uint8_t sdm_enable
        ctypes.POINTER(c_uint),   # uint8_t file_size

        ctypes.POINTER(c_ubyte),    # uint8_t read_key_no
        ctypes.POINTER(c_ubyte),    # uint8_t write_key_no
        ctypes.POINTER(c_ubyte),    # uint8_t read_write_key_no
        ctypes.POINTER(c_ubyte),    # uint8_t change_key_no

        ctypes.POINTER(c_ubyte),    # uint8_t uid_enable
        ctypes.POINTER(c_ubyte),    # uint8_t read_ctr_enable
        ctypes.POINTER(c_ubyte),    # uint8_t read_ctr_limit_enable
        ctypes.POINTER(c_ubyte),    # uint8_t enc_file_data_enable

        ctypes.POINTER(c_ubyte),    # uint8_t meta_data_key_no
        ctypes.POINTER(c_ubyte),    # uint8_t file_data_read_key_no
        ctypes.POINTER(c_ubyte),    # uint8_t read_ctr_key_no

        ctypes.POINTER(c_uint),    # uint8_t uid_offset
        ctypes.POINTER(c_uint),    # uint8_t read_ctr_offset
        ctypes.POINTER(c_uint),    # uint8_t picc_data_offset
        ctypes.POINTER(c_uint),    # uint8_t mac_input_offset
        ctypes.POINTER(c_uint),    # uint8_t enc_offset
        ctypes.POINTER(c_uint),    # uint8_t enc_length
        ctypes.POINTER(c_uint),    # uint8_t mac_offset

        ctypes.POINTER(c_uint),    # read_ctr_limit
        ctypes.POINTER(c_ubyte),   # tt_status_enable
        ctypes.POINTER(c_uint),    # tt_status_offset
    ]

    nt4h_tt_get_file_settingsFunc.restype = c_uint

    return nt4h_tt_get_file_settingsFunc(file_no, file_type, comm_mode, sdm_enable, file_size,
    read_key_no, write_key_no, read_write_key_no, change_key_no,
    uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
    meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
    uid_offset, read_ctr_offset, picc_data_offset,
    mac_input_offset, enc_offset, enc_length, mac_offset, read_ctr_limit,
    tt_status_enable, tt_status_offset)

##########################################################################

def nt4h_check_sdm_mac(sdm_read_counter, uid, auth_key, mac_in_data, mac_in_len, sdm_mac):
    nt4h_check_sdm_macFunc = uFR.nt4h_check_sdm_mac
    nt4h_check_sdm_macFunc.argtypes = [
        c_uint,                     # uint32_t sdm_read_counter
        ctypes.POINTER(c_ubyte),    # uint8_t *uid
        ctypes.POINTER(c_ubyte),    # uint8_t *auth_key
        ctypes.POINTER(c_ubyte),    # uint8_t *mac_in_data
        c_ubyte,                    # uint8_t mac_in_len
        ctypes.POINTER(c_ubyte),   # const uint8_t *sdm_mac
    ]
    nt4h_check_sdm_macFunc.restype = c_uint
    return nt4h_check_sdm_macFunc(sdm_read_counter, uid, auth_key, mac_in_data, mac_in_len, sdm_mac)

##########################################################################

def nt4h_change_key_pk(auth_key, key_no, new_key, old_key):
    nt4h_change_key_pkFunc = uFR.nt4h_change_key_pk
    nt4h_change_key_pkFunc.argtypes = [
        ctypes.POINTER(c_ubyte),    # uint8_t *auth_key
        c_uint,                     # uint8_t key_no
        ctypes.POINTER(c_ubyte),    # uint8_t *old_key
        ctypes.POINTER(c_ubyte),    # uint8_t *new_key
    ]
    nt4h_change_key_pkFunc.restype = c_uint
    return nt4h_change_key_pkFunc(auth_key, key_no, new_key, old_key)

##########################################################################

def LinearWrite_PK(data, linear_address, length, bytes_written, auth_mode, key):
    #UFR_STATUS DL_API LinearWrite_PK(IN const uint8_t *data, uint16_t linear_address, uint16_t length, VAR uint16_t *bytes_written,
    #                                 uint8_t auth_mode, IN const uint8_t *key);

    LinearWrite_PKFunc = uFR.LinearWrite_PK
    LinearWrite_PKFunc.argtypes = [
        ctypes.POINTER(c_ubyte),   # const uint8_t *data
        c_uint16,                 # uint16_t linear_address
        c_uint16,                 # uint16_t length
        POINTER(c_uint16),        # uint16_t *bytes_written
        c_ubyte,                  # uint8_t auth_mode
        ctypes.POINTER(c_ubyte)   # const uint8_t *key
    ]

    LinearWrite_PKFunc.restype = c_uint
    return LinearWrite_PKFunc(data, linear_address, length, byref(bytes_written), auth_mode, key)

##########################################################################

def LinearRead_PK(data, linear_address, length, bytes_written, auth_mode, key):
    #UFR_STATUS DL_API LinearWrite_PK(IN const uint8_t *data, uint16_t linear_address, uint16_t length, VAR uint16_t *bytes_written,
    #                                 uint8_t auth_mode, IN const uint8_t *key);

    LinearRead_PKFunc = uFR.LinearRead_PK
    LinearRead_PKFunc.argtypes = [
        ctypes.POINTER(c_ubyte),   # const uint8_t *data
        c_uint16,                 # uint16_t linear_address
        c_uint16,                 # uint16_t length
        POINTER(c_uint16),        # uint16_t *bytes_written
        c_ubyte,                  # uint8_t auth_mode
        ctypes.POINTER(c_ubyte)   # const uint8_t *key
    ]

    LinearRead_PKFunc.restype = c_uint
    return LinearRead_PKFunc(data, linear_address, length, byref(bytes_written), auth_mode, key)

####################################################################################################################################################

def LinearRead(data, linear_address, length, bytes_written, auth_mode, key):
    #UFR_STATUS DL_API LinearWrite_PK(IN const uint8_t *data, uint16_t linear_address, uint16_t length, VAR uint16_t *bytes_written,
    #                                 uint8_t auth_mode, IN const uint8_t *key);

    LinearReadFunc = uFR.LinearRead
    LinearReadFunc.argtypes = [
        ctypes.POINTER(c_ubyte),   # const uint8_t *data
        c_uint16,                 # uint16_t linear_address
        c_uint16,                 # uint16_t length
        POINTER(c_uint16),        # uint16_t *bytes_read
        c_ubyte,                  # uint8_t auth_mode
        c_ubyte   # const uint8_t *key
    ]

    LinearReadFunc.restype = c_uint
    return LinearReadFunc(data, linear_address, length, byref(bytes_written), auth_mode, key)
##########################################################################
##########################################################################
##########################################################################
def read_and_verify_sdm_data():
    status = 0
    global_file_no = c_ubyte(2)
    global_key_no = c_ubyte(14) # NDEF for SDM must be set as 'Read Access - 14'
    global_comm_mode = c_ubyte(0)

    default_aes_key = (c_ubyte * 16)()
    memset(default_aes_key, 0, ctypes.sizeof(default_aes_key))

    file_no = c_ubyte(2)

    file_type = c_ubyte(0)
    sdm_enable = c_ubyte(0)
    file_size = c_uint(0)

    comm_mode = c_ubyte(0)

    read_key_no = c_ubyte(0)
    write_key_no = c_ubyte(0)
    read_write_key_no = c_ubyte(0)
    change_key_no = c_ubyte(0)

    uid_enable = c_ubyte(0)
    read_ctr_enable = c_ubyte(0)
    read_ctr_limit_enable = c_ubyte(0)
    enc_file_data_enable = c_ubyte(0)

    meta_data_key_no = c_ubyte(0)
    file_data_read_key_no = c_ubyte(0)
    read_ctr_key_no = c_ubyte(0)

    uid_offset = c_uint(0)
    read_ctr_offset = c_uint(0)
    picc_data_offset = c_uint(0)
    mac_input_offset = c_uint(0)

    enc_offset = c_uint(0)
    enc_length = c_uint(0)
    mac_offset = c_uint(0)
    read_ctr_limit = c_uint(0)

    tt_status_enable = c_ubyte(0)
    tt_status_offset = c_uint(0)

    status = nt4h_tt_get_file_settings(file_no, file_type, comm_mode, sdm_enable, file_size,
            read_key_no, write_key_no, read_write_key_no, change_key_no,
            uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
            meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
            uid_offset, read_ctr_offset, picc_data_offset,
            mac_input_offset, enc_offset, enc_length, mac_offset, read_ctr_limit,
            tt_status_enable, tt_status_offset)
    status_str = "nt4h_tt_get_file_settings(): ", uFR_NT4H_Status2String(status)
    print(status_str)
    

    if (status == 0):
        #print("file_type: ", file_type)
        #print("comm_mode: ", comm_mode)
        #print("sdm_enable: ", sdm_enable)
        #print("file_size: ", file_size)
        #print("read_key_no: ", read_key_no)
        #print("write_key_no: ", write_key_no)
        #print("read_write_key_no: ", read_write_key_no)
        #print("change_key_no: ", change_key_no)
        #print("uid_enable: ", uid_enable)
        #print("read_ctr_enable: ", read_ctr_enable)
        #print("read_ctr_limit_enable: ", read_ctr_limit_enable)
        #print("enc_file_data_enable: ", enc_file_data_enable)
        #print("meta_data_key_no: ", meta_data_key_no)
        #print("file_data_read_key_no: ", file_data_read_key_no)
        #print("read_ctr_key_no: ", read_ctr_key_no)
        print("uid_offset: ", uid_offset)
        print("read_ctr_offset: ", read_ctr_offset)
        #print("picc_data_offset: ", picc_data_offset)
        #print("mac_input_offset: ", mac_input_offset)
        #print("enc_offset: ", enc_offset)
        #print("enc_length: ", enc_length)
        print("mac_offset: ", mac_offset)
        #print("read_ctr_limit: ", read_ctr_limit)
        #print("tt_status_enable: ", tt_status_enable)
        #print("tt_status_offset: ", tt_status_offset)
    else:
        return status
    sdm_mode = (sdm_enable.value == 1) and (comm_mode.value == 0) and (read_key_no.value == 0x0E)
    if (sdm_mode == 1):

        status = nt4h_set_global_parameters(global_file_no, global_key_no, global_comm_mode)
        status_str = "nt4h_set_global_parameters(): ", uFR_NT4H_Status2String(status)
        print(status_str)

        if (status != 0):
            return status

        data = (c_ubyte * 256)()
        memset(data, 0, ctypes.sizeof(data))
        read_len = c_uint16(188)
        bytes_read = c_uint16()
        auth_mode = c_ubyte(T4T_AUTHENTICATION["T4T_WITHOUT_PWD_AUTH"])
        status = LinearRead(data, 0, read_len, bytes_read, auth_mode, 0)
        status_str = "LinearRead_PK(): ", uFR_NT4H_Status2String(status)
        print(status_str)
        if (status != 0):
            return status
        
        #print("Data:", ", ".join(f"0x{byte:02X}" for byte in data))
        
        sliced_uid_buffer = slice_c_ubyte_buffer(data, uid_offset.value, uid_offset.value + 14)
        
        hex_uid_string = ''.join(chr(b) for b in sliced_uid_buffer)
        hex_uid_buffer = string_to_hex_buffer(hex_uid_string)
        #print("hex_uid_buffer")
        #print(hex_uid_buffer)

        sliced_sdm_read_counter_buffer = slice_c_ubyte_buffer(data, read_ctr_offset.value, read_ctr_offset.value + 6)
        hex_ctr_string = ''.join(chr(b) for b in sliced_sdm_read_counter_buffer)
        sdm_read_counter = int(hex_ctr_string, 16)
        #print(sdm_read_counter)

        ascii_mac_in = (c_ubyte * 256)()
        memset(ascii_mac_in, 0, ctypes.sizeof(ascii_mac_in))

        mac_in_len = c_ubyte(0)

        sliced_sdm_mac_buffer = slice_c_ubyte_buffer(data, mac_offset.value, mac_offset.value + 16)
        sdm_mac_str = ''.join(chr(b) for b in sliced_sdm_mac_buffer)
        sdm_mac_buffer = string_to_hex_buffer(sdm_mac_str)

        status = nt4h_check_sdm_mac(sdm_read_counter, hex_uid_buffer, default_aes_key, ascii_mac_in, mac_in_len, sdm_mac_buffer)
        status_str = "nt4h_check_sdm_mac(): ", uFR_NT4H_Status2String(status)
        print(status_str)
    else:
        print("File is not in SDM mode.")
    return status
##########################################################################
def log_to_file(uid_str, message, status=None):
    """
    Log messages to a file named with the card's UID.
    
    Args:
        uid_str (str): Card UID used for filename
        message (str): Message to log
        status (int, optional): Status code if applicable
    """
    filename = f"{uid_str}.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(filename, 'a') as f:
        log_entry = f"[{timestamp}] {message}"
        if status is not None:
            log_entry += f" (Status: {uFR_NT4H_Status2String(status)})"
        f.write(log_entry + "\n")
        
    # Still print to console for immediate feedback
    print(message)

##########################################################################
T4T_AUTHENTICATION = {
    "T4T_WITHOUT_PWD_AUTH": 0x60,
    "T4T_PK_PWD_AUTH": 0x80,
    "T4T_RKA_PWD_AUTH": 0x02,
}
##########################################################################
def GetDllVersionStr():
    GetDllVersionStrFunc = uFR.GetDllVersionStr
    GetDllVersionStrFunc.restype = ctypes.c_char_p

    return GetDllVersionStrFunc().decode('utf-8')
##########################################################################
def UFRStatus2String(status):
    ufrStatus2String = uFR.UFR_Status2String
    ufrStatus2String.argtypes = [ c_uint32 ]
    ufrStatus2String.restype = ctypes.c_char_p

    return ufrStatus2String(status).decode('utf-8')
##########################################################################
def uFR_NT4H_Status2String(status):
    if status < 0xC0 or status > 0xCB:
        return UFRStatus2String(status)
    else:
        nt4h_status = f"[0x{status:02X} ({status})] "
        nt4h_status_dict = {
            0xC0: 'NT4H_COMMAND_ABORTED',
            0xC1: 'NT4H_LENGTH_ERROR',
            0xC2: 'NT4H_PARAMETER_ERROR',
            0xC3: 'NT4H_NO_SUCH_KEY',
            0xC4: 'NT4H_PERMISSION_DENIED',
            0xC5: 'NT4H_AUTHENTICATION_DELAY',
            0xC6: 'NT4H_MEMORY_ERROR',
            0xC7: 'NT4H_INTEGRITY_ERROR',
            0xC8: 'NT4H_FILE_NOT_FOUND',
            0xC9: 'NT4H_BOUNDARY_ERROR',
            0xCA: 'NT4H_INVALID_MAC',
            0xCB: 'NT4H_NO_CHANGES'
        }
        nt4h_status += nt4h_status_dict.get(status, '')
        return nt4h_status
##########################################################################
def uid_to_string(uid, uid_size):
    """
    Convert a UID (c_ubyte array) to a string with colon-separated hex bytes.
    
    :param uid: A ctypes array of c_ubyte elements representing the UID.
    :param uid_size: The size of the UID array.
    :return: A colon-separated hex string representation of the UID.
    """
    uid_str = '-'.join(f'{uid[n]:02x}' for n in range(uid_size.value)).upper()
    return uid_str
##########################################################################
def generate_random_aes_key_hex():
    """
    Generate a random 16-byte AES key and return it as a hex string.
    
    :return: A 32-character hexadecimal string representing the AES key.
    """
    key = os.urandom(16)  # Generate 16 random bytes
    return key.hex().upper()  # Convert to a hexadecimal string
##########################################################################
# Function to create a slice of the buffer
def slice_c_ubyte_buffer(buffer, start, end):
    if start < 0 or end > len(buffer) or start > end:
        raise ValueError("Invalid slice range")
    size = end - start
    return (c_ubyte * size)(*buffer[start:end])
##########################################################################
def buffer_to_ascii_string(buffer):
    """Convert an ASCII buffer to a string, replacing non-printable characters with '.'."""
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in buffer)
##########################################################################

old_uid = (c_ubyte * 11)()
def isCardInField():
    
    uid = (c_ubyte * 11)()
    sak = c_ubyte()
    uid_size = c_ubyte()

    status = GetCardIdEx(sak, uid, uid_size)
    if (status == 0):
        uid_str = str()
        card_type = c_ubyte()

        same_card_in_field = True

        for n in range(uid_size.value):
            if (uid[n] != old_uid[n]):
                same_card_in_field = False
                break

        if (same_card_in_field):
            return False
        else:
            for n in range(uid_size.value):
                old_uid[n] = uid[n]

        for n in range(uid_size.value):
            uid_str += '%0.2x' % uid[n] + ':'
        
        status = GetDlogicCardType(card_type)

        if (status == 0) and (uid_size.value > 0):
            print("[ CARD_UID: " + uid_str.upper()[:-1] + " | CARD_TYPE: " + card_types.DLOGIC_CARD_TYPE[card_type.value] + " ]")
            return True
        else:
            memset(old_uid, 0, ctypes.sizeof(old_uid))
            return False
    else: 
        memset(old_uid, 0, ctypes.sizeof(old_uid))
        return False
##########################################################################
def char_to_code(char):
        return ord(char)
##########################################################################
def str_to_hex(string):
    return [ord(c) for c in string]
##########################################################################
# Convert the string back into a hex buffer
def string_to_hex_buffer(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length must be even")
    return (c_ubyte * (len(hex_string) // 2))(
        *(int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2))
    )
##########################################################################

def list_to_ascii_string(data_list):
    """
    Converts a list of integers to a string using ASCII mapping.
    
    :param data_list: List of integers representing ASCII values.
    :return: String decoded from ASCII values.
    """
    # Filter out zeros if they are not part of the intended output
    filtered_list = filter(lambda x: x != 0, data_list)
    return ''.join(map(chr, filtered_list))

def form_sdm_ndef_payload(url):
    # Initial NDEF payload setup
    ndef_with_header = [0x00, 0x00, 0xD1, 0x01, 0x00, 0x55, 0x00]
    ndef_header_len = len(ndef_with_header)
    total_ndef_len = 0

    # Parse URI and add to NDEF payload
    ndef_buffer = str_to_hex(url)
    ndef_with_header.extend(ndef_buffer)
    ndef_with_header.append(char_to_code('?'))
    total_ndef_len = len(ndef_with_header)
    print(total_ndef_len)

    uid_offset = 0
    read_ctr_offset = 0
    mac_offset = 0

    # add UID placeholder data to buffer
    ndef_with_header.extend([char_to_code(c) for c in "uid="])
    ndef_with_header.extend([0] * 14)
    uid_offset = total_ndef_len + 4
    total_ndef_len += 18
    #print("Total len after UID: ")
    #print(total_ndef_len)

    ndef_with_header.append(char_to_code('&'))
    ndef_with_header.extend([char_to_code(c) for c in "ctr="])
    ndef_with_header.extend([0] * 6)
    read_ctr_offset = total_ndef_len + 5
    total_ndef_len += 11
    #print("Total len after CTR: ")
    #print(total_ndef_len)
    
    # add SDM Counter placeholder data to buffer
    ndef_with_header.append(char_to_code('&'))
    ndef_with_header.extend([char_to_code(c) for c in "cmac="])
    ndef_with_header.extend([0] * 16)
    mac_offset = total_ndef_len + 6
    total_ndef_len += 22
    #print("Total len after CMAC: ")
    #print(total_ndef_len)

    # Update NDEF length fields in header bytes
    # ndef_with_header[1] = total ndef message length
    # ndef_with_header[4] = ndef record length
    ndef_with_header[1] = (total_ndef_len - ndef_header_len) + 5
    ndef_with_header[4] = (total_ndef_len - ndef_header_len) + 1

    #print(total_ndef_len)

    result = {}
    result["sdm_payload"] = ndef_with_header
    result["sdm_payload_length"] = total_ndef_len
    result["uid_offset"] = uid_offset
    result["read_ctr_offset"] = read_ctr_offset
    result["mac_offset"] = mac_offset

    return result

def add_additional_ndef_payload_parameter(sdm_payload, param_name, param_value):
    #print("Payload:", ", ".join(f"0x{byte:02X}" for byte in sdm_payload))
    ndef_message_length = sdm_payload[1]
    ndef_record_length = sdm_payload[4]

    #print("NDEF Message length", ndef_message_length)
    #print("NDEF Record length", ndef_record_length)

    sdm_payload.append(char_to_code('&'))
    sdm_payload.extend([char_to_code(c) for c in param_name])
    sdm_payload.append(char_to_code('='))
    sdm_payload.extend([char_to_code(c) for c in param_value])

    extended_len = len(param_name) + len(param_value) + 2

    sdm_payload[1] = ndef_message_length + extended_len
    sdm_payload[4] = ndef_record_length + extended_len

    # Storing the result in a dictionary
    result = {}
    result["extended_payload"] = sdm_payload
    result["extended_payload_length"] = len(sdm_payload)

    return result
##########################################################################
if __name__ == '__main__':
    print("---------------------------------------------")
    print("https://www.d-logic.com/nfc-rfid-reader-sdk/")
    print("---------------------------------------------")
    print("NTAG424 DNA Programmer, version 1.0")
    print("---------------------------------------------")

    print("Trying to establish communication with the reader...")

    print(f"[DLL_VERSION = {GetDllVersionStr()}]")

    status = ReaderOpen()
    status_str = "ReaderOpen(): " + uFR_NT4H_Status2String(status)
    print(status_str)
    if (status != 0):
        exit(1)
    
    print("> PROGRAMMING BEGIN. ")

    print("> 1. Get card UID")
    uid = (c_ubyte * 11)()
    sak = c_ubyte()
    uid_size = c_ubyte()
    card_uid_str = str()

    status = GetCardIdEx(sak, uid, uid_size)
    if (status == 0):
        card_uid_str = uid_to_string(uid, uid_size)
        log_to_file(card_uid_str, f"Card UID successfully retrieved: {card_uid_str}")
    else:
        print("Failed to retrieve card UID. Exiting...")
        exit(1)
    
    print("> 2. Form SDM NDEF Payload...")
    uri = "https://raygen.ch/"
    formed_result = form_sdm_ndef_payload(uri)
    sdm_payload = formed_result["sdm_payload"]
    sdm_payload_length = formed_result["sdm_payload_length"]
    uid_offset = formed_result["uid_offset"]
    read_ctr_offset = formed_result["read_ctr_offset"]
    mac_offset = formed_result["mac_offset"]

    sdm_payload_str = buffer_to_ascii_string(sdm_payload)
    log_to_file(card_uid_str, f"    Payload [ASCII] = {sdm_payload_str}")

    print("> 3. Add additional parameter to NDEF outside of SDM")
    
    extended_payload_result = add_additional_ndef_payload_parameter(sdm_payload, "test", "12345678")

    extended_payload = extended_payload_result["extended_payload"]
    extended_payload_length = extended_payload_result["extended_payload_length"]
    log_to_file(card_uid_str, "Additional NDEF parameters added")

    print("> 4. Write SDM payload")
    file_no = c_ubyte(2)                # File number
    key_no = c_ubyte(0)                 # Write key no
    communication_mode = c_ubyte(0)     # Communication mode
    status = nt4h_set_global_parameters(file_no, key_no, communication_mode)

    default_aes_key = (c_ubyte * 16)()
    memset(default_aes_key, 0, ctypes.sizeof(default_aes_key))
    write_data_buffer = (c_ubyte * len(extended_payload))(*extended_payload)
    write_len = c_uint16(extended_payload_length)
    bytes_written = c_uint16()
    auth_mode = c_ubyte(T4T_AUTHENTICATION["T4T_PK_PWD_AUTH"])
    
    status = LinearWrite_PK(write_data_buffer, 0, write_len, bytes_written, auth_mode, default_aes_key)
    if (status == 0):
        log_to_file(card_uid_str, "NDEF Message written successfully")
    else:
        log_to_file(card_uid_str, "Failed to write NDEF message", status)
        exit(1)

    print("> 5. Change SDM settings")
    communication_mode = c_ubyte(3)
    new_communication_mode = c_ubyte(0)

    read_key_no = c_ubyte(0x0E)
    write_key_no = c_ubyte(0)
    read_write_key_no = c_ubyte(0)
    change_key_no = c_ubyte(0)

    uid_enable = c_ubyte(1)
    read_ctr_enable = c_ubyte(1)
    read_ctr_limit_enable = c_ubyte(0)
    enc_file_data_enable = c_ubyte(0)

    meta_data_key_no = c_ubyte(0x0E)
    file_data_read_key_no = c_ubyte(0)
    read_ctr_key_no = c_ubyte(0)

    picc_data_offset = c_uint(0)
    mac_input_offset = c_uint(mac_offset)
    enc_offset = c_uint(0)
    enc_length = c_uint(0)
    read_ctr_limit = c_uint(0)

    tt_status_enable = c_ubyte(0)
    tt_status_offset = c_uint(0)

    status = nt4h_tt_change_sdm_file_settings_pk(default_aes_key, file_no, key_no, communication_mode, new_communication_mode, 
                            read_key_no, write_key_no, read_write_key_no, change_key_no,
                            uid_enable, read_ctr_enable, read_ctr_limit_enable, enc_file_data_enable,
                            meta_data_key_no, file_data_read_key_no, read_ctr_key_no,
                            uid_offset, read_ctr_offset, picc_data_offset, mac_input_offset,
                            enc_offset, enc_length, mac_offset, read_ctr_limit, 
                            tt_status_enable, tt_status_offset)
    if (status == 0):
        log_to_file(card_uid_str, "SDM settings set successfully")
    else:
        log_to_file(card_uid_str, "Failed to set SDM settings", status)
        exit(1)

    """
    print(">>>> Try reading data...")
    if (status == 0):
        log_to_file(card_uid_str, "SDM data verified successfully")
    else:
        log_to_file(card_uid_str, "Failed to verify SDM data", status)
        exit(1)
    """
    
    print("6. Change Master key")
    new_aes_key_str = generate_random_aes_key_hex()
    #print(f"Randomized key is: {new_aes_key_str}")
    new_aes_key = string_to_hex_buffer(new_aes_key_str)
    
    status = nt4h_change_key_pk(default_aes_key, 0, new_aes_key, default_aes_key)
    if (status == 0):
        log_to_file(card_uid_str, f"Card master key changed successfully to: {new_aes_key_str}")
    else:
        log_to_file(card_uid_str, "Failed to change card master key", status)
        exit(1)
    
    ReaderClose()