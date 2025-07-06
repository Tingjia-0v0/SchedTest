import sys
import os
import json

def main():
    if len(sys.argv) != 3:
        print("Usage: python update_kernel_config.py <kernel_config_file> new-config-file")
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

    with open(kernel_config_file, 'w') as file:
        # if config_name is not in the file, add it
        for config_name, config_value in new_config.items():
            updated = False
            for i, line in enumerate(lines):
                if line.startswith("#") and len(line.split(' ')) > 2 and line.split(' ')[1] == config_name and "is not set" in line:
                    lines[i] = "\n" # remove the line
                elif line.split('=')[0] == config_name:
                    lines[i] = f"{config_name}={config_value}\n"
                    updated = True
            if not updated:
                lines.append(f"{config_name}={config_value}\n")

        file.writelines(lines)
    


if __name__ == "__main__":
    main()