from cryptonice import scanner
import argparse
import json

from cryptonice.__init__ import __version__
cryptonice_version=__version__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="JSON input file of scan commands")
    args = parser.parse_args()

    input_file = args.input_file
    with open(input_file) as f:
        input_data = json.load(f)
        input_data.update({'cn_version': cryptonice_version})


    output_data, hostname = scanner.scanner_driver(input_data)
    if output_data is None and hostname is None:
        print('Error with input - scan was not completed')


if __name__ == "__main__":
    main()
