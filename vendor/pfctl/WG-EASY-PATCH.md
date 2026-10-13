This is pfctl 0.7.0 from crates.io, published by Mullvad VPN, with its original
MIT and Apache licences retained. `PfCtl::add_anchor_first` and read-only `anchor_exists` are added.

The existing insertion method places anchors by priority, behind other anchors
of equal priority. wg-easy needs its temporary full-tunnel filter first and
`quick`, so another firewall's earlier pass rule cannot leak physical traffic.
The new method uses the existing native ioctl wrappers and ticket management.
This can be removed when upstream provides an equivalent public API.

`Icmp6Type` also exposes the standard multicast listener query/report/done types
(130, 131, 132 and 143). These and the existing IPv6 neighbor/router discovery
types match code zero. wg-easy permits link-local multicast maintenance so a
snooping switch does not expire the membership needed for neighbor discovery.
