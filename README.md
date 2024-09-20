A Python-based CLI for PN532 and PN532Killer.

## Hardware
- PN532 with USB Serial Chip on HSU Mode
- [PN532Killer](https://pn532killer.com) 

## Usage
Run the example script with the following command:
```bash
cd script
python pn532_cli_main.py
```

## Requirements
- Python 3.5
- pySerial

## Protocols
### PN532
- [ISO14443A](https://www.nxp.com/docs/en/user-guide/141520.pdf)
### PN532Killer
- [ISO14443](https://pn532killer.com)
- [ISO15693](https://pn532killer.com)
- [EM4100](https://pn532killer.com)

## Credits
[libnfc](https://github.com/nfc-tools/libnfc)  
[Proxmark3](https://github.com/RfidResearchGroup/proxmark3)   
[Chameleon Ultra](https://github.com/RfidResearchGroup/ChameleonUltra)   

## License

The MIT License (MIT)
Copyright (c) 2016 Manuel Fernando Galindo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
