#!/usr/bin/env python3

import psutil
import argparse
import logging
import time
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the script.
    """
    parser = argparse.ArgumentParser(description='Monitors network connections and alerts on new or unexpected connections.')
    parser.add_argument('-i', '--interval', type=int, default=5, help='Interval in seconds to check for new connections.')
    parser.add_argument('-f', '--file', type=str, default='known_connections.json', help='File to store known connections.')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('-o', '--output', type=str, help='Output file for new connections (JSON format).')  #Added output argument
    return parser.parse_args()

def get_current_connections():
    """
    Retrieves the current network connections using psutil.
    Returns:
        dict: A dictionary of connection details.  Keys are a hash of the connection, values are connection details.
    """
    connections = {}
    for conn in psutil.net_connections(kind='inet'):
        try:
            # Sanity check to avoid exceptions
            if conn.laddr and conn.raddr:
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"

                # Check if pid is valid
                if conn.pid is not None and psutil.pid_exists(conn.pid):
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        logging.warning(f"Could not get process name for PID {conn.pid}: {e}")
                        process_name = "Unknown"
                else:
                    process_name = "System" # Or None if no process is found

                # Hash the connection details to use as a key
                connection_hash = hash(f"{conn.pid}-{local_address}-{remote_address}-{conn.status}")
                connections[connection_hash] = {
                    'pid': conn.pid,
                    'local_address': local_address,
                    'remote_address': remote_address,
                    'status': conn.status,
                    'process_name': process_name,
                    'family': str(conn.family),
                    'type': str(conn.type)
                }
        except Exception as e:
            logging.error(f"Error processing connection: {e}")

    return connections

def load_known_connections(file_path):
    """
    Loads known connections from a JSON file.
    Args:
        file_path (str): The path to the JSON file.
    Returns:
        dict: A dictionary of known connections.
    """
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        else:
            return {}
    except FileNotFoundError:
        logging.warning(f"File not found: {file_path}. Starting with an empty known connections list.")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {file_path}. Starting with an empty known connections list.")
        return {}
    except Exception as e:
        logging.error(f"Error loading known connections: {e}. Starting with an empty known connections list.")
        return {}

def save_known_connections(connections, file_path):
    """
    Saves known connections to a JSON file.
    Args:
        connections (dict): The dictionary of connections to save.
        file_path (str): The path to the JSON file.
    """
    try:
        with open(file_path, 'w') as f:
            json.dump(connections, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving known connections to {file_path}: {e}")

def check_for_new_connections(known_connections, current_connections, output_file=None):
    """
    Checks for new connections and alerts if any are found.
    Args:
        known_connections (dict): A dictionary of known connections.
        current_connections (dict): A dictionary of current connections.
        output_file (str, optional): File path for writing new connections. Defaults to None.
    """
    new_connections = {}
    for connection_hash, connection_details in current_connections.items():
        if connection_hash not in known_connections:
            logging.warning(f"New connection detected: {connection_details}")
            new_connections[connection_hash] = connection_details

    if new_connections:
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(new_connections, f, indent=4)
                logging.info(f"New connections written to {output_file}")
            except Exception as e:
                logging.error(f"Error writing new connections to {output_file}: {e}")
        else:
            logging.info("New connections found, but no output file specified.")
    else:
        logging.info("No new connections detected.")

    return new_connections

def main():
    """
    Main function to run the network connection monitor.
    """
    args = setup_argparse()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled.")

    known_connections_file = args.file
    interval = args.interval
    output_file = args.output

    known_connections = load_known_connections(known_connections_file)

    try:
        while True:
            current_connections = get_current_connections()
            new_connections = check_for_new_connections(known_connections, current_connections, output_file)

            # Update known connections, adding new connections to the dictionary.  We only store the hashes.
            known_connections.update(current_connections)

            save_known_connections(known_connections, known_connections_file)

            time.sleep(interval)

    except KeyboardInterrupt:
        logging.info("Exiting program.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        logging.info("Program terminated.")

if __name__ == "__main__":
    # Example usage:
    # 1. Run the monitor with default settings:  python3 monitor_networkconnections.py
    # 2. Run with a custom interval: python3 monitor_networkconnections.py -i 10
    # 3. Run with a custom known connections file: python3 monitor_networkconnections.py -f my_connections.json
    # 4. Enable debug logging: python3 monitor_networkconnections.py -d
    # 5. Output new connections to a file: python3 monitor_networkconnections.py -o new_connections.json
    main()