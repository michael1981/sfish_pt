
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14156);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2004:057-1: tripwire");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:057-1 (tripwire).");
 script_set_attribute(attribute: "description", value: "Paul Herman discovered a format string vulnerability in tripwire that
could allow a local user to execute arbitrary code with the rights of
the user running tripwire (typically root). This vulnerability only
exists when tripwire is generating an email report.
Update:
The packages previously released for Mandrakelinux 9.2 would segfault
when doing a check due to compilation problems. The updated packages
correct the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:057-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0536");
script_summary(english: "Check for the version of the tripwire package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tripwire-2.3.1.2-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tripwire-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0536", value:TRUE);
}
exit(0, "Host is not affected");
