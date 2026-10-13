This is pfctl 0.7.0 from crates.io, published by Mullvad VPN, with its original
MIT and Apache licences retained. `PfCtl::add_anchor_first` and read-only `anchor_exists` are added.

The existing insertion method places anchors by priority, behind other anchors
of equal priority. wg-easy needs its temporary full-tunnel filter first and
`quick`, so another firewall's earlier pass rule cannot leak physical traffic.
The new method uses the existing native ioctl wrappers and ticket management.
This can be removed when upstream provides an equivalent public API.
