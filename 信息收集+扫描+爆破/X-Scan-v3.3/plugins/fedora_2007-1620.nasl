
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1620
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27725);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1620: Terminal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1620 (Terminal)");
 script_set_attribute(attribute: "description", value: "Terminal is a lightweight and easy to use terminal emulator application
for the X windowing system, with some new ideas and features that make
it unique among X terminal emulators.

-
ChangeLog:


Update information :

* Tue Aug 14 2007 Kevin Fenzi <kevin tummy com> - 0.2.6-3
- Add patch for CVE-2007-3770.
- Update License tag
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3770");
script_summary(english: "Check for the version of the Terminal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"Terminal-0.2.6-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
