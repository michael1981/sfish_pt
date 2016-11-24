
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8314
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34284);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-8314: rkhunter");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8314 (rkhunter)");
 script_set_attribute(attribute: "description", value: "Rootkit Hunter (RKH) is an easy-to-use tool which checks
computers running UNIX (clones) for the presence of rootkits
and other unwanted tools.

-
ChangeLog:


Update information :

* Wed Sep  3 2008 Kevin Fenzi <kevin tummy com> - 1.3.2-5
- Patch debug tmp file issue - bug #460628
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the rkhunter package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"rkhunter-1.3.2-5.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
