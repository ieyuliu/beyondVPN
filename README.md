## Introduction

This open source project is associated with our published work "Beyond the VPN: Practical Client Identity in an Internet with Widespread IP Address Sharing" accepted by Local Computer Networks (LCN), 2020, and in submission work "Avoiding VPN Bottlenecks: Network-Level Client Identity Validation at the Server Firewall". 

This project aims to provide information to help organizations with recognizing end users, and explore the possibility to replace VPN, which has much redundant functionalities, when it is used just for access control. More details please refer to our <a href="https://web.cs.wpi.edu/~yliu25/publications/lcn2020.pdf">publication</a>. This proof-of-work implementation of this project is open sourced since we intend to help people who need it can deploy the technology fast. One can modify and re-distributed this implementation.

This project is based on software-defined networking (SDN) architecture. The system is designed for usages in home networks and host devices that have an SDN agent reside in. Thus this repo contains an SDN module that inserts the unique user identifier from the source of a network request. The SDN module is developed upon <i>floodlight</i>, a popular SDN framework. On enterprise end, we develop modules upon <a href="https://github.com/nawawi/xtables-addons"><i>xtables-addons-3.0</i></a> framework, which embeds into <i>iptables</i>. So organizations could use it conveniently by set up firewall rules. The setup process needs to follow the manual of 


### iptables module description

The below files are located in `../xtables-addons-3.0/extension` directory of xtables-addons architecture. One can develop upon the files, compile and configure these modules in the same directory. Jan provided thorough <a href='http://inai.de/documents/Netfilter_Modules.pdf'>tutorial</a> about how to develop an xtables-addons module, which is very helpful to understand this project. 

>libxt\_cookies.c
>libxt\_cookies.h

Module starts with `libxt_` runs in user space. These two files defines the command that network operators may enter from iptables. Here is an example: 

`iptables -t mangle -I PREROUTING -m cookies --id 123 -j IPIPDECAP`

`-m cookies` specifies this module. `--id 123` specifies the rules of specific user. `-j IPIPDECAP` specifies the action that how to process this matched packet. These information took from command line is parsed and registered with the kernel module. 

>xt\_cookies.c
>xt\_cookies.h

Module starts with `'xt_'` runs in the kernel. These two files  are match modules. It returns results of validating a user with a preregistered identifier. If it is matched, it executes the actions defined by the target module in the command. In the example above, `-j IPIPDECAP` is the target module that we develop, which defines the action. 

>xt\_IPIPDECAP.c
>xt\_IPIPDECAP.h

These two files are target modules. If a packet is matched, and the rules specified `IPIPDECAP`, it decapsulate the packet from IP-in-IP to the original packet. This step is important to maintain the application server can deploy our system in a seamless manner. More details about IP-in-IP and why it is used can be found in our paper mentioned above. 


>xt\_IPIPENCAP.c
>xt\_IPIPENCAP.h

This module is a target module. It should be configured by network operators or any automated software to issue unique identifier to a remote user. It encapsulates a packet into IP-in-IP packet, and the inner IP header is used for conveying such identifier. It will be decapsulated by the SDN controller on end users' end. More details please refer to the paper I mentioned above. 

### SDN controller

All the modules are developed for <i>floodlight</i>

> cgnIPEncap.java

This file detects the user's request packet and encapsulate the packet to an IP-in-IP packet. The reason of doing so can be found in our paper.

> cgnIPDecap.java

This file takes the response packet from the authentication server or applications server. It decapsulates the packet from IP-in-IP to original packet to let end host accept it. Detailed reasons of doing so can be found in our publication. 




