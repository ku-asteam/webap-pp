# WEBap-pp: Packet processing module for web applications in wired-cum-wireless environments

WEBap-pp enables a user to emulate switch packet proceesing on a software switch.

## Requirements
* Linux kernel 3.18.11
* Software switch with multiple NICs
* At least two servers connected to the software switch

## Usage
* Build the source as a Linux kernel module
* Configure ipv4_forwarding in Linux
* Configure IP address of each eth port
* Insert the moudle into the kernel
