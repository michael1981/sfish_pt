
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5018
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33116);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-5018: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5018 (evolution)");
 script_set_attribute(attribute: "description", value: "Evolution is the GNOME mailer, calendar, contact manager and
communications tool.  The tools which make up Evolution will
be tightly integrated with one another and act as a seamless
personal information-management tool.

-
Update Information:

Fix two buffer overflows in iCalendar .ics file fromat support discovered and
reported by Alin Rad Pop of the Secunia Research: CVE-2008-1108, CVE-2008-1109,
SA30298    See referenced bugzilla bugs or Secunia advisories for further
details:    [9]http://secunia.com/advisories/30298
[10]http://secunia.com/secunia_research/2008-22/advisory/
[11]http://secunia.com/secunia_research/2008-23/advisory/
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0072", "CVE-2008-1108", "CVE-2008-1109");
script_summary(english: "Check for the version of the evolution package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"evolution-2.10.3-10.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
