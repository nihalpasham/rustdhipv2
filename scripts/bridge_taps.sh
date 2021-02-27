#!/bin/bash

ip tuntap add name tap0 mode tap user root
ip tuntap add name tap1 mode tap user root
brctl addbr br0
brctl addif br0 tap0 tap1 
ip link set tap0 up
ip link set tap1 up
ip link set br0 up