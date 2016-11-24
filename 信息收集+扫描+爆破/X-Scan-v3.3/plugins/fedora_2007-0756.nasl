
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0756
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27679);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-0756: HelixPlayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0756 (HelixPlayer)");
 script_set_attribute(attribute: "description", value: "Helix Player is an open-source media player built in the Helix
Community for consumers. Built using GTK, it plays open source formats,
like Ogg Vorbis and Theora using the powerful Helix DNA Client Media
Engine.

-
Update Information:

A buffer overflow flaw was discovered in the way RealPlayer and HelixPlayer han
dle the wallclock variable in Synchronized Multimedia Integration Language (SMI
L) files.

More information regarding this flaw can be found here:
[8]http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=547
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3410");
script_summary(english: "Check for the version of the HelixPlayer package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"HelixPlayer-1.0.7-6.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
