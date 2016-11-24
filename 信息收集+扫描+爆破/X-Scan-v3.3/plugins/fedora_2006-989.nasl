
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-989
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24183);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 5 2006-989: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-989 (gzip)");
 script_set_attribute(attribute: "description", value: "The gzip package contains the popular GNU gzip data compression
program. Gzipped files have a .gz extension.

Gzip should be installed on your Red Hat Linux system, because it is a
very commonly used data compression program.



Update information :

* Wed Sep 20 2006 Ivana Varekova <varekova redhat com> 1.3.5-7.fc5
- fix bug 204676 (patches by Tavis Ormandy)
- cve-2006-4334 - null dereference problem
- cve-2006-4335 - buffer overflow problem
- cve-2006-4336 - buffer underflow problem
- cve-2006-4338 - infinite loop problem
- cve-2006-4337 - buffer overflow problem

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gzip-1.3.5-7.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
