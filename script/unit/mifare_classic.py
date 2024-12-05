def get_block_size_by_sector(sector):
    if sector < 32:
        return 4
    elif sector < 40:
        return 16
    else:
        return 0

def get_block_index_by_sector(sector):
    if sector < 32:
        return sector * 4
    elif sector < 40:
        return 128 + (sector - 32) * 16
    else:
        return 0

def is_trailer_block(block_index):
    if block_index < 128:
        return (block_index + 1) % 4 == 0
    else:
        return (block_index + 1 - 128) % 16 == 0
