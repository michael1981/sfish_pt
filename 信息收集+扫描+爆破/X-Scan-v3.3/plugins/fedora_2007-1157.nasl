
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1157
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27701);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1157: blam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1157 (blam)");
 script_set_attribute(attribute: "description", value: "Blam is a tool that helps you keep track of the growing
number of news feeds distributed as RSS. Blam lets you
subscribe to any number of feeds and provides an easy to
use and clean interface to stay up to date

-
Update Information:

Updated firefox packages that fix several security bugs are now available for F
edora 7.

Users of Blam are advised to upgrade to this errata package, which has been reb
uilt against the updated Firefox package.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
script_summary(english: "Check for the version of the blam package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"blam-1.8.3-5.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
