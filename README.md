# soapsniffer
HTTP Soap sniffer.

Captures network traffic and filters SOAP messages out of them.
The SOAP messages are printed to STDOUT, so this program can be used in a pipe construction.


### Compiling

```bash
chmod +x ./autogen.sh && ./autogen.sh
make && make install
```

### Shipping from source

```bash
./autogen.sh && make maintainer-clean && rm -rf m4
```

### Usage

|    Argument    | Function |
| -------------- | -------- |
| -i <interface> | Listen for packets on specified interface. |
| -f <filter>    | Specify a pcap capture filter (same syntax as in tcpdump/tshark) |
| -d             | Output debugging info to STDERR. Can be secified up to 5 times for more debuging |


### Why?

First of all, we wanted to have a program who can output the tcp payloads to STDOUT in clear text.
This is why tcpdump was not of any good use for us.

So we looked into tshark and ran it for a time.
But what we found was that tshark has some pretty nasty memory leaks and that it should be used with files, rather then STDOUT.

