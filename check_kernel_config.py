import sys
import os
import json

def main():
    if len(sys.argv) != 3:
        print("Usage: python check_kernel_config.py <kernel_config_file> <new-config-file>")
        sys.exit(1)

    kernel_config_file = sys.argv[1]
    new_config_file = sys.argv[2]
    if not os.path.exists(kernel_config_file):
        print(f"Error: {kernel_config_file} does not exist")
        sys.exit(1)
    
    with open(new_config_file, 'r') as file:
        new_config = json.load(file)

    with open(kernel_config_file, 'r') as file:
        lines = file.readlines()
        # if config_name is not in the file, add it
        for config_name, config_value in new_config.items():
            exists = False
            for i, line in enumerate(lines):
                if line.split('=')[0] == config_name:
                    if "=".join(line.split('=')[1:]).strip() != config_value:
                        print(f"Warning: Config {config_name} is not set to {config_value}")
                        return False
                    exists = True
            if not exists and config_value == "y":
                print(f"Warning: Config {config_name} is not set to {config_value}")
                return False

    return True


if __name__ == "__main__":
    main()