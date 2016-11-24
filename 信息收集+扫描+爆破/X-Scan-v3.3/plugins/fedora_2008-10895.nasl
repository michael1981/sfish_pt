
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-10895
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38122);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-10895: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-10895 (cups)");
 script_set_attribute(attribute: "description", value: "The Common UNIX Printing System provides a portable printing layer for
UNIXÂ® operating systems. It has been developed by Easy Software Products
to promote a standard printing solution for all UNIX vendors and users.
CUPS provides the System V and Berkeley command-line interfaces.

-
Update Information:

Security update to fix CVE-2008-5183.    Also changed in this update:    * a bu
g
that caused cups-polld to fail to resolve hostnames has been fixed  * a bug tha
t
could cause libcups to get stuck in a loop has been fixed  * the dnssd backend
has been removed as it is not working correctly and can prevent printers being
added
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1722", "CVE-2008-5183", "CVE-2008-5286");
script_summary(english: "Check for the version of the cups package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"cups-1.3.9-4.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
