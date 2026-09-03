# Changelog

What changed in purdungeon, newest first, in plain language. The layout follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added

- **Devices introduce themselves, and purdungeon listens.** DHCP (host name, vendor class, request-list fingerprint, domain), NetBIOS name registrations, mDNS and LLMNR answers, SNMP system-group responses, and LLDP/CDP announcements (system name, description, capabilities, port, management address) are read into an evidence table: one row per device, kind, value and source protocol, with a confidence and how often it was said. The device panel lists every row, so a claim in the report can be traced to the packets that made it.
- **Names on devices.** The best-evidenced name fills the Name row, and labels devices that have no address of their own.
- **Switches heard only over LLDP or CDP are assets now**, keyed by MAC, with their announced name, model, port and capabilities. So is a DHCP client that never got an address.
- **ARP corrects MAC addresses.** A device first seen through a router used to keep the router's MAC; ARP, DHCP and LLDP/CDP name the device's own and now outrank a frame's.
- **Roles from evidence.** A device that describes itself as a switch operating system, or announces bridge/router capability, becomes network gear; one that describes itself as a SIMATIC S7, Logix, Modicon, MELSEC or Sysmac controller becomes a PLC; an operator panel becomes an HMI; a Windows machine (per DHCP) becomes a workstation unless it serves something a workstation would not. Each such role quotes the evidence and names its source. Traffic still comes first: a device that answers Modbus is a PLC whatever it announces.
- **Operating-system guesses from DHCP**, stated as guesses: the vendor class outranks the request-list fingerprint, and both carry a confidence below any self-declared fact.
- **Devices seen only in ARP are now assets.** An ARP announcement is enough to put a device on the map with its MAC address and vendor. Its evidence line says "seen only in ARP; no IP traffic", so silence at the IP layer is never mistaken for absence. A whole subnet can be inventoried from ARP alone.
- **IPv6 devices and conversations** are read like IPv4 ones. IPv6 multicast addresses are treated like broadcast and kept off the map. Global IPv6 addresses count as external, so the "external address on the OT segment" finding can fire for them too.
- **VLAN tags are read.** Every conversation records the 802.1Q VLAN it was seen on (the outer tag for double-tagged frames), and the device, link and conversation panels show it.
- **More capture types load:** `tcpdump -i any` (Linux cooked, both header versions), raw-IP and loopback captures. Devices in those captures have no MAC address, and the panels say so instead of inventing one.
- **LLDP and CDP announcements are recognised and counted.** Their contents (switch port, system name, capabilities) will feed device identity in a later release.
- **IP protocols other than TCP, UDP and ICMP** — IGMP, VRRP, GRE, ESP, OSPF, … — appear as port-less conversations named by protocol instead of vanishing. On a vessel those are exactly the redundancy and tunnel conduits worth seeing.
- **Honest frame accounting.** The header now explains every frame that could not be decoded, by reason: unreadable link type, non-IP frame, IP fragment, cut by the snapshot length, unreadable, or without a timestamp. It also shows how many link-layer announcements were counted. The numbers always add up to the frames in the file.
- **Tests you can trust:** golden-file tests against three public ICS captures and a synthetic one, a fetch-only corpus manifest with checksums (`just fetch-corpus`), a `cargo deny` licence policy that rejects anything copyleft, and a CI workflow that runs on Linux and Windows.

### Changed

- A client that has no address yet (`0.0.0.0`) is treated like a broadcast address and kept off the map; its DHCP facts go to the device itself.
- A capture whose writer was killed mid-packet now imports everything before the cut instead of failing outright; the stub is counted as unreadable.
- Packet counts in the header and the sources list include ARP, LLDP and CDP frames, so they are higher than before for the same file.
- Search understands IPv6 subnets (`fe80::/64`) and IP protocol names (`vrrp`, `igmp`). Long IPv6 node labels are shortened on the canvas; the panels show the full address.
- The error shown for a capture with nothing readable now lists what was read and why it was skipped.

### Known limitations

- A dual-stack device appears once per address (IPv4, IPv6 global, IPv6 link-local). Merging addresses into one device by MAC is planned.
- IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are separate devices from their IPv4 twins.
- An LLDP or CDP announcement is tied to a device by its management address, else by the one device known to own the sender MAC; when neither is clear the announcement becomes its own MAC-only device rather than being guessed onto a neighbour.
- SNMP v3 and LLDP-MED / organisation-specific TLVs are not read.
