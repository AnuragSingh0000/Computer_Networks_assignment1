# Computer Networks Assignment 1
This is the repository for Question 1

### Prerequisites
You'll need Python 3.6 or newer and the following libraries:

1. `dpkt`: A fast, simple packet creation and parsing library.

2. `json`: The standard library for working with JSON data.

You can install `dpkt` using `pip`:

``` bash
pip install dpkt
```

Additionally, You would have to download the `5.pcap` file from this link https://drive.google.com/drive/folders/1_LhhdsAA7miN91GcRTKOPZOWroQQNGWV 

### Files

- `rules.json`: This file contains the rules for routing packets.

- `helper.py`: This script provides essential functions for packet manipulation and routing logic.

- `client.py`: The client-side script that reads DNS queries from a pcap file and sends them to the server.

- `server.py`: The server-side script that receives packets, applies  rules, and sends DNS responses with the correct IP addresses.


### How to Run 

Follow these steps to run the application:

1. Open two separate terminal windows.

2. Start the Server:
In the first terminal, run the server script. The server will start listening for incoming connections on port 23354. You should see a confirmation message once it's up and running.
```bash
python3 server.py
```
The output will look like this:
```
Server Socket successfully created
<socket.socket fd=3, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('0.0.0.0', 23354)>
```
3. Run the Client:
In the second terminal, run the client script. The client will read the 5.pcap file, process each DNS query, and send it to the server.

```Bash

python3 client.py
```
You will see a series of outputs in both terminals as the client sends queries and the server responds.

4. Observe the Output:
The client terminal will show the DNS queries being sent and the responses being received from the server. Finally, it will display a summary table of the headers, domains, and resolved IPs, along with the total number of packets processed.
The server terminal will show each incoming connection and the IP address assigned to each packet based on the routing rules in rules.json.
After the client has processed all packets from the .pcap file, it will close its connection, and the server will shut down.
