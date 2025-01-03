# uFCoder libraries

Scope of this project are libraries used with **uFR** and **uFR Zero** Series devices and SDK examples. 
Libraries are supported at following platforms:
Windows 32 and 64 bit (static and dynamic)
Linux 32 and 64 bit (dynamic & static)
Linux ARM and ARM-HF (dynamic & static)
Mac OSX 64 bit & Universal (dynamic only)
iOS 64 bit (static & framework)
Android ARM 64 bit (.aar)
ESP32 ESP-IDF component
## Getting Started

Download project, choose appropriate architecture and place a library in appropriate directory.
Consult documentation for [API reference](https://code.d-logic.com/nfc-rfid-reader-sdk/ufr-doc/-/blob/master/uFR_Series_NFC_reader_API.pdf). For quick insight and functions' prototypes, check **/include/ufCoder.h** header file. 


### Prerequisites

[**uFR**](https://webshop.d-logic.com/products/nfc-rfid-reader-writer/ufr-series-dev-tools-with-sdk.html) or [**uFR Zero**](https://webshop.d-logic.com/products/nfc-rfid-reader-writer/ufr-zero-series.html) Series reader.


## License

See the [uFR_library_license.md](/license/uFR_library_license.md) file for details

## Acknowledgments

* Libraries are specific to mentioned hardware ONLY and some other hardware might have different approach, please bear that in mind.  

## Changelog
### [Version 6.0.6] - 2024-12-18
### General Changes
- **API Updates:**
  - *ReaderOpen()* algorithm updated and refactored. Updated support for **uFR Zero** series readers for the purpose of improved connection. Function algorithm now excludes deprecated features. See [Deprecations](#Deprecations) section for more details.

### Platform-Specific Changes
#### Windows
- Mandatory `FTD2XX.dll` dependency is now considered optional, and will be loaded in runtime on *as-needed* basis. 
#### Linux
- Enhanced support for `/dev/ttyUSBXX` port handling when working with `ftdi_sio` module.

#### Android
- The `FTD2XX ` driver dependency of the Android library has been updated to support devices running *Android 14* and resolve related issues.

### Bug Fixes
- *ReaderOpen()* resolved issue with port open via GPIO pins on `Raspbian OS`
- *ReaderOpen()* resolved issue with port closure before new port open on `Windows`
- *ReaderReset()* bug with **uFR Zero** readers on Linux & macOS fixed. Additional patch for `Rasbpian OS` when using GPIO pins or [Raspberry Pi NFC shield](https://webshop.d-logic.com/raspberry-pi-nfc-shield.html)

### Deprecations
- *ReaderOpen()* - Excluded support for `UWP` platform and readers working on 250K baudrate (BaseHD series).
- `UWP (Universal Windows Platform)` libraries are considered deprecated and may be updated on *as-needed* basis.