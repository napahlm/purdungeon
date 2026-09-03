# Changelog

What changed in purdungeon, newest first, in plain language. The layout follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added

- **Devices seen only in ARP are now assets.** An ARP announcement is enough to put a device on the map with its MAC address and vendor. Its evidence line says "seen only in ARP; no IP traffic", so silence at the IP layer is never mistaken for absence. A whole subnet can be inventoried from ARP alone.
- **IPv6 devices and conversations** are read like IPv4 ones. IPv6 multicast addresses are treated like broadcast and kept off the map. Global IPv6 addresses count as external, so the "external address on the OT segment" finding can fire for them too.
- **VLAN tags are read.** Every conversation records the 802.1Q VLAN it was seen on (the outer tag for double-tagged frames), and the device, link and conversation panels show it.
- **More capture types load:** `tcpdump -i any` (Linux cooked, both header versions), raw-IP and loopback captures. Devices in those captures have no MAC address, and the panels say so instead of inventing one.
- **LLDP and CDP announcements are recognised and counted.** Their contents (switch port, system name, capabilities) will feed device identity in a later release.
- **IP protocols other than TCP, UDP and ICMP** — IGMP, VRRP, GRE, ESP, OSPF, … — appear as port-less conversations named by protocol instead of vanishing. On a vessel those are exactly the redundancy and tunnel conduits worth seeing.
- **Honest frame accounting.** The header now explains every frame that could not be decoded, by reason: unreadable link type, non-IP frame, IP fragment, cut by the snapshot length, unreadable, or without a timestamp. It also shows how many link-layer announcements were counted. The numbers always add up to the frames in the file.
- **Tests you can trust:** golden-file tests against three public ICS captures and a synthetic one, a fetch-only corpus manifest with checksums (`just fetch-corpus`), a `cargo deny` licence policy that rejects anything copyleft, and a CI workflow that runs on Linux and Windows.

### Changed

- A capture whose writer was killed mid-packet now imports everything before the cut instead of failing outright; the stub is counted as unreadable.
- Packet counts in the header and the sources list include ARP, LLDP and CDP frames, so they are higher than before for the same file.
- Search understands IPv6 subnets (`fe80::/64`) and IP protocol names (`vrrp`, `igmp`). Long IPv6 node labels are shortened on the canvas; the panels show the full address.
- The error shown for a capture with nothing readable now lists what was read and why it was skipped.

### Known limitations

- A dual-stack device appears once per address (IPv4, IPv6 global, IPv6 link-local). Merging addresses into one device by MAC is planned.
- IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are separate devices from their IPv4 twins.
- Devices that appear only in LLDP or CDP are not yet assets; that needs the device evidence table planned for the next release.
- The MAC stored for a device is the one on the first frame seen. For a device beyond a router that is the router's MAC; ARP will be allowed to correct it once evidence is tracked per source.
