
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6760
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39546);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-6760: deluge");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6760 (deluge)");
 script_set_attribute(attribute: "description", value: "Deluge is a new BitTorrent client, created using Python and GTK+. It is
intended to bring a native, full-featured client to Linux GTK+ desktop
environments such as GNOME and XFCE. It supports features such as DHT
(Distributed Hash Tables), PEX (ÂµTorrent-compatible Peer Exchange), and UPnP
(Universal Plug-n-Play) that allow one to more easily share BitTorrent data
even from behind a router with virtually zero configuration of port-forwarding.

-
Update Information:

Deluge 1.1.9 contains updated translations and fixes for a 'move torrent' issue
(now only happens when the torrent has data downloaded), a folder renaming bug
(renaming a parent folder into multiple folders), and an issue with adding a
remote torrent in the WebUI.    This update also includes all upstream bug-fixe
s
and enhancements in versions 1.1.7 and 1.1.8 (which were skipped in this
package). For a full list of these changes, please see the upstream changelog:
[9]http://dev.deluge-torrent.org/wiki/ChangeLog    In addition, the included co
py
of rb_libtorrent has been updated to fix a potential directory traversal
vulnerability which would allow a remote attacker to create or overwrite
arbitrary files via a '..' (dot dot) and partial relative pathname in a
specially-crafted torrent.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1760");
script_summary(english: "Check for the version of the deluge package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"deluge-1.1.9-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
