## shorewall-nft-netkit

Low-level netns / TUN-TAP / packet-construction primitives shared by
`shorewall-nft-simlab` and future `shorewall-nft-stagelab`.  Contains
`tundev` (ioctl-based TUN/TAP creation), `nsstub` (fork-based named
network-namespace lifecycle with `PR_SET_PDEATHSIG` cleanup), and
`packets` (Scapy-backed probe builders + fast scapy-free ARP/NDP path).
