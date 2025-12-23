#!/usr/bin/env python3
"""
PN532Killer DFU (Device Firmware Update) Tool

Standalone script for updating PN532Killer firmware via serial port.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from pn532_dfu import Pn532KillerDfu, load_firmware


def print_hex(label: str, data: bytes) -> None:
    """Print hex data with label."""
    hex_str = " ".join(f"{b:02X}" for b in data)
    print(f"{label}: {hex_str}")


def main():
    parser = argparse.ArgumentParser(description="PN532Killer Firmware Update Tool")
    parser.add_argument("--port", required=True, help="Serial port (e.g., /dev/ttyUSB0, COM3)")
    parser.add_argument("--bin", required=True, help="Firmware binary file path")
    parser.add_argument("--force", action="store_true", help="Skip automatic DFU mode entry (manually hold button and plug USB)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=float, default=2.0, help="Serial timeout in seconds (default: 2.0)")
    
    args = parser.parse_args()

    # Load firmware
    try:
        firmware_data = load_firmware(args.bin)
    except Exception as e:
        print(f"[ERR] Failed to load firmware: {e}")
        return 1

    print(f"Firmware size: {len(firmware_data)} bytes")

    # Initialize DFU
    dfu = Pn532KillerDfu(args.port, timeout=args.timeout, verbose=args.verbose)
    
    try:
        if args.force:
            # Force mode: skip automatic DFU entry, user must manually enter DFU mode
            print(f"\n{'='*60}")
            print(f"FORCE MODE: Manual DFU Entry Required")
            print(f"{'='*60}")
            print(f"1. HOLD the button on the device")
            print(f"2. While holding, PLUG IN the USB cable")
            print(f"3. Release the button after USB is connected")
            print(f"4. The device should now be in DFU mode")
            print(f"5. Press ENTER to start firmware update")
            print(f"{'='*60}\n")
            
            input("Press ENTER when device is in DFU mode...")
            
            # Open serial port directly in DFU mode (921600 baud)
            print(f"\nOpening port: {args.port} at 921600 baud")
            dfu.open(dfu_mode=True)
            
            # Even in manual DFU mode, we need to "wake up" the bootloader
            # This mimics Android's initDfuStream() behavior
            if args.verbose:
                print("[DFU] Triggering bootloader wake-up sequence...")
            
            if dfu.serial:
                # Clear buffers first
                dfu.serial.reset_input_buffer()
                dfu.serial.reset_output_buffer()
                
                # Trigger bootloader (same as Android initDfuStream)
                dfu.serial.rts = True
                dfu.serial.dtr = True
                if args.verbose:
                    print("[DFU] RTS=True, DTR=True")
                time.sleep(0.2)
                
                dfu.serial.rts = False
                if args.verbose:
                    print("[DFU] RTS=False (bootloader should respond)")
                
                # Wait for bootloader to stabilize
                time.sleep(0.5)
                
                # Check if there's any startup message from bootloader
                if dfu.serial.in_waiting > 0:
                    startup_msg = dfu.serial.read(dfu.serial.in_waiting)
                    if args.verbose:
                        print(f"[DFU] Bootloader message ({len(startup_msg)} bytes): {startup_msg.hex()}")
                
                # Clear buffers again
                dfu.serial.reset_input_buffer()
                dfu.serial.reset_output_buffer()
            
            print("Bootloader wake-up complete, ready to communicate")
            
            # Additional delay before first command
            time.sleep(0.3)
            
            # Test if serial port is working
            if args.verbose and dfu.serial:
                print(f"[DEBUG] Serial port status:")
                print(f"  - Port: {dfu.serial.port}")
                print(f"  - Baudrate: {dfu.serial.baudrate}")
                print(f"  - Open: {dfu.serial.is_open}")
                print(f"  - DTR: {dfu.serial.dtr}, RTS: {dfu.serial.rts}")
                print(f"  - Bytes in buffer: {dfu.serial.in_waiting}")
        else:
            # Normal mode: automatic DFU entry
            print(f"\n{'='*60}")
            print(f"IMPORTANT: Device Preparation")
            print(f"{'='*60}")
            print(f"1. Please UNPLUG the device USB cable now")
            print(f"2. Wait 3 seconds")
            print(f"3. REPLUG the USB cable")
            print(f"4. Press ENTER immediately after replugging")
            print(f"{'='*60}\n")
            
            input("Press ENTER when ready...")
            
            # Open serial port
            print(f"\nOpening port: {args.port}")
            dfu.open()
            
            # Enter DFU mode
            print("Entering DFU mode...")
            if not dfu.enter_dfu(verbose=args.verbose):
                print("[ERR] Failed to enter DFU mode")
                return 1
            print("Entered DFU (921600 baud, RTS/DTR toggled)")
            
            # Wait for device to be ready
            time.sleep(0.3)
        
        # Get device init info
        print("Getting device init info...")
        init_info = dfu.get_device_init_info()
        
        if init_info is None:
            if args.force:
                # In force mode, use default values if device info retrieval fails
                print("[WARN] Could not get device info, using default values for PN532Killer")
                from unit.ad15_firmware_util import DeviceInitInfo
                # Default values based on typical PN532Killer configuration
                # These values should match what the device would return
                init_info = DeviceInitInfo(
                    status=0,
                    zone_addr=0x100,           # 256 bytes header
                    upgrade_len=0,              # Will be calculated
                    flash_eoffset_size=0x0,     # Start from beginning of flash
                    erase_unit_size=4096        # 4KB erase unit (standard sector size)
                )
                print(f"Using default configuration:")
                print(f"  - Zone Address: 0x{init_info.zone_addr:X} ({init_info.zone_addr} bytes)")
                print(f"  - Flash Offset: 0x{init_info.flash_eoffset_size:X}")
                print(f"  - Erase Unit: {init_info.erase_unit_size} bytes")
                print(f"[WARN] If upgrade fails, try without --force to get actual device values")
            else:
                print("[ERR] Device init failed in DFU mode.")
                return 1
        else:
            print(f"Device Info:")
            print(f"  - Zone Address: 0x{init_info.zone_addr:X}")
            print(f"  - Upgrade Length: {init_info.upgrade_len}")
            print(f"  - Flash Offset: 0x{init_info.flash_eoffset_size:X}")
            print(f"  - Erase Unit: {init_info.erase_unit_size} bytes")
            
            # Get device check info
            check_info = dfu.get_device_check_info()
            if check_info:
                print(f"Chip Info:")
                print(f"  - VID: 0x{check_info.vid:04X}")
                print(f"  - PID: 0x{check_info.pid:X}")
                print(f"  - SDK ID: 0x{check_info.sdk_id:X}")
        
        # Validate firmware size
        if len(firmware_data) <= init_info.zone_addr:
            print(f"[ERR] Firmware file is smaller than zone address; aborting.")
            return 1
        
        # Calculate blocks
        file_size = len(firmware_data) - init_info.zone_addr
        block_count = (file_size + init_info.erase_unit_size - 1) // init_info.erase_unit_size
        aligned_size = block_count * init_info.erase_unit_size
        
        # Pad firmware if needed
        if aligned_size != file_size:
            print(f"Padding firmware: {file_size} -> {aligned_size} bytes")
            firmware_data = firmware_data + bytes([0xFF]) * (aligned_size - file_size)
        
        # Extract upgrade buffer
        file_buf = firmware_data[init_info.zone_addr : init_info.zone_addr + aligned_size]
        
        # Calculate file CRC list
        print(f"Calculating CRC for {block_count} blocks...")
        file_crc_list = Pn532KillerDfu.get_buffer_crc_list(
            file_buf, block_count, init_info.erase_unit_size
        )
        if args.verbose:
            print(f"File CRC: {' '.join(f'{v:04X}' for v in file_crc_list)}")
        
        # Force update all blocks (no CRC comparison)
        chip_crc_list = [0] * block_count
        
        # Update firmware
        upgrade_addr = init_info.flash_eoffset_size
        blocks_updated = 0
        
        def print_progress(current, total, prefix="Progress", suffix="", length=50):
            """Print progress bar"""
            percent = current / total
            filled = int(length * percent)
            bar = '█' * filled + '-' * (length - filled)
            print(f'\r{prefix} |{bar}| {percent*100:.1f}% {suffix}', end='', flush=True)
        
        print(f"\nUpdating {block_count} blocks...")
        for idx in range(block_count):
            offset = idx * init_info.erase_unit_size
            
            # Erase block
            print_progress(idx * 2, block_count * 2, prefix="Erasing", suffix=f"Block {idx+1}/{block_count}")
            if not dfu.erase_flash(upgrade_addr + offset, init_info.erase_unit_size):
                print(f"\n[ERR] Erase failed at block {idx}")
                return 1
            
            # Write block
            print_progress(idx * 2 + 1, block_count * 2, prefix="Writing", suffix=f"Block {idx+1}/{block_count}")
            chunk = file_buf[offset : offset + init_info.erase_unit_size]
            if not dfu.write_flash(
                chunk, upgrade_addr + offset, init_info.erase_unit_size, erase_unit=4096
            ):
                print(f"\n[ERR] Write failed at block {idx}")
                return 1
            
            blocks_updated += 1
        
        # Complete progress bar
        print_progress(block_count * 2, block_count * 2, prefix="Complete", suffix=f"{blocks_updated}/{block_count} blocks")
        print()  # New line after progress bar
        
        # Verify firmware
        print("Verifying firmware...")
        new_chip_crc_list = dfu.get_chip_crc_list(
            init_info.flash_eoffset_size, block_count, init_info.erase_unit_size
        )
        
        if args.verbose:
            print(f"New Chip CRC: {' '.join(f'{v:04X}' for v in new_chip_crc_list)}")
        
        if new_chip_crc_list == file_crc_list:
            print("✓ Firmware update successful!")
            print("Rebooting device...")
            dfu.dfu_reboot()
            return 0
        else:
            print("✗ Firmware verification failed!")
            print("Device will NOT be rebooted.")
            return 1
            
    except KeyboardInterrupt:
        print("\n[!] Update interrupted by user")
        return 1
    except Exception as e:
        print(f"[ERR] Update failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        dfu.close()
        print("Port closed")


if __name__ == "__main__":
    sys.exit(main())
