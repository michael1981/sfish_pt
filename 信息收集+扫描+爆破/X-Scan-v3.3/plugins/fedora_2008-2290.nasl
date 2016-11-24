
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2290
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31374);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-2290: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2290 (evolution)");
 script_set_attribute(attribute: "description", value: "Evolution is the GNOME mailer, calendar, contact manager and
communications tool.  The tools which make up Evolution will
be tightly integrated with one another and act as a seamless
personal information-management tool.

-
Update Information:

Ulf HÃ¤rnhammar of Secunia Research discovered a format string flaw  in the way
Evolution displayed encrypted mail content. If a user opened a carefully crafte
d
mail message, arbitrary code could be executed as the user running Evolution.
(CVE-2008-0072)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0072");
script_summary(english: "Check for the version of the evolution package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"evolution-2.10.3-8.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
