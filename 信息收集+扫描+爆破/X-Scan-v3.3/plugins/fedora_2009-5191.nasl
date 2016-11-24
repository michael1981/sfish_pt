
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5191
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38837);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-5191: nsd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5191 (nsd)");
 script_set_attribute(attribute: "description", value: "NSD is a complete implementation of an authoritative DNS name server.
For further information about what NSD is and what NSD is not please
consult the REQUIREMENTS document which is a part of this distribution
(thanks to Olaf).

-
Update Information:

Security release.    A one-byte overflow bug allows a carefully crafted exploit
to bring down your DNS server. It is highly unlikely that this one byte overflo
w
can lead to other (system) exploits.
[9]http://www.nlnetlabs.nl/publications/NSD_vulnerability_announcement.html
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the nsd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"nsd-3.2.2-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
