All-in-one PN532 comes with buit-in CH340 USB Serial chip and PN532 chip. This is a simple Python script that demonstrates how to read NFC tags using the PN532 chip. The script uses the pySerial library to communicate with the PN532 chip over a serial connection. 
This is not the library based on libnfc, but the uart communication with the PN532 chip.

## Usage
Run the example script with the following command:
```bash
cd script
python pn532_cli_main.py
```

## Requirements
- Python 3.5
- pySerial
- PN532 with USB Serial Chip (CH340, FT232RL, CP2102, etc.)

## Credits
[libnfc](https://github.com/nfc-tools/libnfc)  
[Chameleon Ultra](https://github.com/RfidResearchGroup/ChameleonUltra)  

## License

The MIT License (MIT)
Copyright (c) 2016 Manuel Fernando Galindo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
