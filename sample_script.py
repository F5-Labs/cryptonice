from cryptonice import scanner
import argparse
import json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="JSON input file of scan commands")
    args = parser.parse_args()

    input_file = args.input_file
    with open(input_file) as f:
        input_data = json.load(f)

    output_data, hostname = scanner.scanner_driver(input_data)

    if output_data is not None and hostname is not None:
        scanner.writeToJSONFile(hostname, output_data)
    else:
        print("Error with input - scan was not completed")


if __name__ == "__main__":
    main()