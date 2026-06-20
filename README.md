# Network-Packet-Sniffer-Analyzer
A lightweight CLI tool that captures raw network packets, decodes them down to the protocol level (Ethernet -> IPv4 -> TCP/UDP), and flags TCP traffic that matches known stealth-scan signatures. Built in Python first, transitioned to C later

Architecture

NIC/Kernel
    |
    v
capture.py
(Producer Thread) ------- bounded queue-------> pipeline.py
                    (drop oldest when full)   (consumer thread)
                                                    |
                                                    v
                                                engine.py
                                              (runs Detectors)

