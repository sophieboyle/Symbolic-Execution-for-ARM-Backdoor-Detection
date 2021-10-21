from capstone import *
import argparse

def arg_parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs=1, 
                        help='Filename of firmware to analyse')
    args = parser.parse_args()
    return args.filename[0]

def read_bytes(filename):
    with open(filename, "rb") as f:
        bytes_str = f.read()
    return bytes_str

def main():
    filename = arg_parsing()
    firmware_bytes = read_bytes(filename)

if __name__ == '__main__':
    main()
