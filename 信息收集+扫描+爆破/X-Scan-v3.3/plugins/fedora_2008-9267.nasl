
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9267
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34701);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-9267: ktorrent");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9267 (ktorrent)");
 script_set_attribute(attribute: "description", value: "KTorrent is a BitTorrent program for KDE. Its main features are native KDE
integration, download of torrent files, upload speed capping, internet
searching using various search engines, UDP Trackers and UPnP support.

-
ChangeLog:


Update information :

* Wed Oct 29 2008 Rex Dieter <rdieter fedoraproject org> - 2.2.7-2
- multiple security issues in the web interface (#469020)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the ktorrent package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ktorrent-2.2.7-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
