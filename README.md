![Banner](banner.png)

# monitor-networkconnections
Monitors network connections in three reported classes: established connections, listeners, and UDP endpoints. Each connection is reported with its process ID, local and remote addresses and ports, connection state, and its class, and the tool alerts on new or unexpected connections. Other connection states, such as TIME_WAIT, are not reported. - Focused on System monitoring and alerts

Connections are keyed by a SHA256 digest of the process ID, addresses, status, and process name, so the known connections file survives restarts without re-alerting or duplicating connections that are already known. Entries absent from the enumeration for 3 cycles in a row are pruned from the known connections file, and that file is saved only when the map changed. When an output file is named, all new connections found during the run are accumulated in it, instead of each cycle replacing the previous batch. A non positive interval is refused at startup with status 1. If enumerating connections is denied, the tool names that plainly as access denied and exits with status 1.

## Install
`git clone https://github.com/ShadowStrikeHQ/monitor-networkconnections`

## Usage
`./monitor-networkconnections [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: Interval in seconds to check for new connections.
- `-f`: File to store known connections.
- `-d`: Enable debug logging.
- `-o`: Output file for new connections (JSON format). New connections accumulate in this file across the run.

## License
Copyright (c) ShadowStrikeHQ
