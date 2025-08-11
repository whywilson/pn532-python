import pn532_com
from pn532_cmd import Pn532CMD

from platform import uname

def test_fn():
    dev = pn532_com.Pn532Com()
    port_name = "tcp:192.168.20.58:18889"
    try:
        dev.open(port_name)
        if not dev.isOpen():
            print(f"Failed to connect to {port_name}")
            return
        print(f"Connected to {port_name}")
        cml = Pn532CMD(dev)
    except Exception as e:
        print(f"Connection failed: {e}")
        return
    try:
        print("Getting firmware version...")
        fw_version = cml.get_firmware_version()
        print("FW Version:", fw_version)
        hf_14a_scan_result = cml.hf_14a_scan()
        if hf_14a_scan_result is not None:
            for data_tag in hf_14a_scan_result:
                print(f"- UID: {data_tag['uid'].hex().upper()}")
                print(
                    f"- ATQA: {data_tag['atqa'].hex().upper()} "
                    f"(0x{int.from_bytes(data_tag['atqa'], byteorder='little'):04x})"
                )
                print(f"- SAK: {data_tag['sak'].hex().upper()}")
                if "ats" in data_tag and len(data_tag["ats"]) > 0:
                    print(f"- ATS: {data_tag['ats'].hex().upper()}")
            
            
        else:
            print("ISO14443-A Tag not found")
        
        # 测试 hf mf cview 命令
        print("\nTesting HF MF cview...")
        try:
            cview_result = cml.hfmf_cview()  # 装饰器直接返回 parsed 数据
            if cview_result is not None:
                print("✅ HF MF cview succeeded")
                if isinstance(cview_result, dict):
                    print(f"  - Available keys: {list(cview_result.keys())}")
                    # 显示标签信息
                    if 'uid' in cview_result:
                        print(f"  - UID: {cview_result['uid']}")
                    if 'atqa' in cview_result:
                        print(f"  - ATQA: {cview_result['atqa']}")
                    if 'sak' in cview_result:
                        print(f"  - SAK: {cview_result['sak']}")
                    if 'blocks' in cview_result:
                        print(f"  - Total blocks read: {len(cview_result['blocks'])}")
                        print("  - Block data preview (first 5 blocks):")
                        for i in range(min(5, len(cview_result['blocks']))):
                            block_key = str(i)
                            if block_key in cview_result['blocks']:
                                print(f"    Block {i:02d}: {cview_result['blocks'][block_key]}")
                    elif 'data' in cview_result:
                        print(f"  - Data field found: {type(cview_result['data'])}")
                        if isinstance(cview_result['data'], list):
                            print(f"  - Data list length: {len(cview_result['data'])}")
                            print("  - Data preview (first 5 items):")
                            for i, item in enumerate(cview_result['data'][:5]):
                                print(f"    Item {i}: {item}")
                        else:
                            print(f"  - Data content: {cview_result['data']}")
                    else:
                        print("  - No 'blocks' or 'data' found")
                else:
                    print(f"  - Result type: {type(cview_result)}")
            else:
                print("❌ HF MF cview returned None")
        except Exception as e:
            print(f"❌ ERROR during HF MF cview: {e}")
            import traceback
            traceback.print_exc()
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()
    dev.close()

if __name__ == "__main__":
    test_fn()
