#!/usr/bin/env python3
"""
Torrent file parser and validator for mktorrent test suite.
This script parses and validates torrent files produced by mktorrent tests.
"""

import sys
import os
import json
import hashlib
from collections import OrderedDict

def decode_bencoded_data(data, pos=0):
    """Decode bencoded data starting at position pos."""
    if data[pos:pos+1] == b'd':  # Dictionary
        pos += 1
        result = OrderedDict()
        while pos < len(data) and data[pos:pos+1] != b'e':
            key, pos = decode_bencoded_data(data, pos)
            if isinstance(key, bytes):
                key = key.decode('utf-8', errors='replace')  # Dictionary keys are strings
            value, pos = decode_bencoded_data(data, pos)
            result[key] = value
        return result, pos + 1  # Skip 'e'
    elif data[pos:pos+1] == b'l':  # List
        pos += 1
        result = []
        while pos < len(data) and data[pos:pos+1] != b'e':
            value, pos = decode_bencoded_data(data, pos)
            result.append(value)
        return result, pos + 1  # Skip 'e'
    elif data[pos:pos+1] == b'i':  # Integer
        end = data.find(b'e', pos)
        value = int(data[pos+1:end])
        return value, end + 1
    elif data[pos:pos+1].isdigit():  # String
        colon = data.find(b':', pos)
        length = int(data[pos:colon])
        start = colon + 1
        end = start + length
        return data[start:end], end
    else:
        raise ValueError(f"Invalid bencoded data at position {pos}: {data[pos:pos+10]}")

def parse_torrent(filepath):
    """Parse a torrent file and return its parsed contents."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        parsed_data, _ = decode_bencoded_data(data)
        return parsed_data
    except Exception as e:
        print(f"Error parsing torrent file {filepath}: {e}")
        return None

def validate_torrent_structure(torrent_data):
    """Validate the structure of a torrent file."""
    required_keys = ['info', 'announce']
    info_keys = ['piece length', 'pieces']
    
    # Check required keys
    missing_keys = [key for key in required_keys if key not in torrent_data]
    if missing_keys:
        return False, f"Missing required keys: {', '.join(missing_keys)}"
    
    # Check info keys
    info = torrent_data['info']
    missing_info_keys = [key for key in info_keys if key not in info]
    if missing_info_keys:
        return False, f"Missing required info keys: {', '.join(missing_info_keys)}"
    
    # Check for either files (multi-file) or length (single-file)
    if 'files' not in info and 'length' not in info:
        return False, "Missing either 'files' or 'length' in info"
    
    # Check pieces
    if len(info['pieces']) % 20 != 0:
        return False, "Invalid pieces length (must be multiple of 20)"
    
    return True, "Torrent structure is valid"

def get_file_info(torrent_data):
    """Get file information from a torrent file."""
    info = torrent_data['info']
    
    if 'files' in info:
        # Multi-file torrent
        files = []
        total_size = 0
        for file_info in info['files']:
            path = '/'.join([p.decode('utf-8', errors='replace') if isinstance(p, bytes) else p for p in file_info['path']])
            size = file_info['length']
            total_size += size
            files.append({'path': path, 'size': size})
        
        return {'name': info['name'].decode('utf-8', errors='replace') if isinstance(info['name'], bytes) else info['name'],
                'is_directory': True,
                'file_count': len(files),
                'total_size': total_size,
                'files': files}
    else:
        # Single-file torrent
        return {'name': info['name'].decode('utf-8', errors='replace') if isinstance(info['name'], bytes) else info['name'],
                'is_directory': False,
                'file_count': 1,
                'total_size': info['length'],
                'files': [{'path': info['name'].decode('utf-8', errors='replace') if isinstance(info['name'], bytes) else info['name'], 
                           'size': info['length']}]}

def get_announce_info(torrent_data):
    """Get announce information from a torrent file."""
    if 'announce' not in torrent_data:
        return {'announce': None, 'announce_list': None}
    
    announce = torrent_data['announce'].decode('utf-8', errors='replace') if isinstance(torrent_data['announce'], bytes) else torrent_data['announce']
    
    if 'announce-list' in torrent_data:
        announce_list = []
        for tier in torrent_data['announce-list']:
            tier_urls = []
            for url in tier:
                tier_urls.append(url.decode('utf-8', errors='replace') if isinstance(url, bytes) else url)
            announce_list.append(tier_urls)
        return {'announce': announce, 'announce_list': announce_list}
    
    return {'announce': announce, 'announce_list': None}

def get_piece_info(torrent_data):
    """Get piece information from a torrent file."""
    info = torrent_data['info']
    piece_length = info['piece length']
    pieces_raw = info['pieces']
    
    # Split pieces into 20-byte SHA-1 hashes
    pieces = []
    for i in range(0, len(pieces_raw), 20):
        pieces.append(pieces_raw[i:i+20].hex())
    
    return {
        'piece_length': piece_length,
        'piece_count': len(pieces),
        'pieces': pieces
    }

def get_creation_info(torrent_data):
    """Get creation information from a torrent file."""
    result = {}
    
    if 'creation date' in torrent_data:
        result['creation_date'] = torrent_data['creation date']
    
    if 'created by' in torrent_data:
        created_by = torrent_data['created by']
        result['created_by'] = created_by.decode('utf-8', errors='replace') if isinstance(created_by, bytes) else created_by
    
    if 'comment' in torrent_data:
        comment = torrent_data['comment']
        result['comment'] = comment.decode('utf-8', errors='replace') if isinstance(comment, bytes) else comment
    
    # Check for private flag
    if 'info' in torrent_data and 'private' in torrent_data['info']:
        result['private'] = bool(torrent_data['info']['private'])
    
    # Skip info hash calculation since we don't have bencode module
    # This would require pip install bencode.py
    
    return result

def main():
    """Main function for the script."""
    if len(sys.argv) < 2:
        print("Usage: python torrent_parser.py <torrent_file> [--validate] [--json] [--full]")
        return 1
    
    torrent_file = sys.argv[1]
    validate = '--validate' in sys.argv
    output_json = '--json' in sys.argv
    full_output = '--full' in sys.argv
    
    if not os.path.isfile(torrent_file):
        print(f"Error: Torrent file '{torrent_file}' not found.")
        return 1
    
    torrent_data = parse_torrent(torrent_file)
    if not torrent_data:
        return 1
    
    if validate:
        valid, message = validate_torrent_structure(torrent_data)
        if not valid:
            print(f"Validation failed: {message}")
            return 1
        print(f"Validation successful: {message}")
    
    # Extract and display useful information
    file_info = get_file_info(torrent_data)
    announce_info = get_announce_info(torrent_data)
    piece_info = get_piece_info(torrent_data)
    creation_info = get_creation_info(torrent_data)
    
    result = {
        'file': os.path.basename(torrent_file),
        'file_info': file_info,
        'announce_info': announce_info,
        'piece_info': piece_info,
        'creation_info': creation_info
    }
    
    if full_output:
        # Include the full torrent data
        result['full_data'] = str(torrent_data)
    
    if output_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Torrent: {os.path.basename(torrent_file)}")
        print(f"Name: {file_info['name']}")
        print(f"Type: {'Directory' if file_info['is_directory'] else 'Single File'}")
        print(f"File count: {file_info['file_count']}")
        print(f"Total size: {file_info['total_size']} bytes")
        print(f"Piece length: {piece_info['piece_length']} bytes")
        print(f"Piece count: {piece_info['piece_count']}")
        print(f"Announce URL: {announce_info['announce']}")
        
        if 'creation_date' in creation_info:
            import datetime
            date_str = datetime.datetime.fromtimestamp(creation_info['creation_date']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Creation date: {date_str}")
        
        if 'created_by' in creation_info:
            print(f"Created by: {creation_info['created_by']}")
        
        if 'comment' in creation_info:
            print(f"Comment: {creation_info['comment']}")
        
        if 'private' in creation_info:
            print(f"Private: {'Yes' if creation_info['private'] else 'No'}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 
