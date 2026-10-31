#!/usr/bin/env python3

import psutil
import argparse
import hashlib
import logging
import socket
import sys
import time
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Entries absent from the enumeration for this many cycles in a row
# are pruned from the known connections map.
PRUNE_AFTER_MISSING_CYCLES = 3

def setup_argparse():
    parser = argparse.ArgumentParser(description='Monitors network connections and alerts on new or unexpected connections.')
    parser.add_argument('-i', '--interval', type=int, default=5, help='Interval in seconds to check for new connections.')
    parser.add_argument('-f', '--file', type=str, default='known_connections.json', help='File to store known connections.')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('-o', '--output', type=str, help='Output file for new connections (JSON format).')
    return parser.parse_args()

def connection_key(pid, local_address, remote_address, status, process_name):
    plain = f"{pid}|{local_address}|{remote_address}|{status}|{process_name}"
    return hashlib.sha256(plain.encode('utf-8')).hexdigest()

def is_udp(conn):
    conn_type = getattr(conn, 'type', None)
    if conn_type == socket.SOCK_DGRAM:
        return True
    text = str(conn_type)
    return text.endswith('SOCK_DGRAM') or text == str(socket.SOCK_DGRAM)

def classify_connection(conn):
    """Returns listener, udp_endpoint, or established, or None to skip."""
    status = str(conn.status)
    if status == 'LISTEN':
        return 'listener'
    if is_udp(conn):
        return 'udp_endpoint'
    if not conn.raddr:
        return 'listener'
    if status == 'ESTABLISHED':
        return 'established'
    return None

def get_current_connections():
    connections = {}
    for conn in psutil.net_connections(kind='inet'):
        try:
            if not conn.laddr:
                continue
            connection_class = classify_connection(conn)
            if connection_class is None:
                continue
            local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
            remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            if conn.pid is not None and psutil.pid_exists(conn.pid):
                try:
                    process = psutil.Process(conn.pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logging.warning(f"Could not get process name for PID {conn.pid}: {e}")
                    process_name = "Unknown"
            else:
                process_name = "System"
            key = connection_key(conn.pid, local_address, remote_address, conn.status, process_name)
            connections[key] = {
                'pid': conn.pid,
                'local_address': local_address,
                'remote_address': remote_address,
                'status': conn.status,
                'process_name': process_name,
                'connection_class': connection_class,
                'family': str(conn.family),
                'type': str(conn.type)
            }
        except psutil.AccessDenied:
            raise
        except Exception as e:
            logging.error(f"Error processing connection: {e}")
    return connections

def load_known_connections(file_path):
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
    try:
        with open(file_path, 'w') as f:
            json.dump(connections, f, indent=4)
        return True
    except Exception as e:
        logging.error(f"Error saving known connections to {file_path}: {e}")
        return False

def check_for_new_connections(known_connections, current_connections, output_file=None):
    new_connections = {}
    for key, connection_details in current_connections.items():
        if key not in known_connections:
            logging.warning(f"New connection detected ({connection_details.get('connection_class', 'unknown')}): {connection_details}")
            new_connections[key] = connection_details
    if new_connections:
        if output_file:
            try:
                accumulated = {}
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            loaded = json.load(f)
                        if isinstance(loaded, dict):
                            accumulated = loaded
                    except (OSError, json.JSONDecodeError):
                        logging.error(f"Error reading existing output file {output_file}. Starting a new accumulated output.")
                accumulated.update(new_connections)
                with open(output_file, 'w') as f:
                    json.dump(accumulated, f, indent=4)
                logging.info(f"New connections written to {output_file}")
            except Exception as e:
                logging.error(f"Error writing new connections to {output_file}: {e}")
        else:
            logging.info("New connections found, but no output file specified.")
    else:
        logging.info("No new connections detected.")
    return new_connections

def main():
    args = setup_argparse()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled.")
    if args.interval <= 0:
        logging.error("Error: Interval must be a positive value.")
        sys.exit(1)
    known_connections_file = args.file
    interval = args.interval
    output_file = args.output
    known_connections = load_known_connections(known_connections_file)
    missing_cycles = {key: 0 for key in known_connections}
    try:
        while True:
            try:
                current_connections = get_current_connections()
            except psutil.AccessDenied as e:
                logging.error(f"Access denied while enumerating network connections: {e}")
                sys.exit(1)
            new_connections = check_for_new_connections(known_connections, current_connections, output_file)
            changed = False
            for key, details in current_connections.items():
                if key not in known_connections or known_connections[key] != details:
                    changed = True
                missing_cycles[key] = 0
            known_connections.update(current_connections)
            for key in list(known_connections.keys()):
                if key not in current_connections:
                    missing_cycles[key] = missing_cycles.get(key, 0) + 1
                    if missing_cycles[key] >= PRUNE_AFTER_MISSING_CYCLES:
                        logging.info(f"Pruning known connection absent for {PRUNE_AFTER_MISSING_CYCLES} cycles: {key}")
                        del known_connections[key]
                        missing_cycles.pop(key, None)
                        changed = True
            if changed:
                save_known_connections(known_connections, known_connections_file)
            time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Exiting program.")
    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        logging.info("Program terminated.")

if __name__ == "__main__":
    main()
