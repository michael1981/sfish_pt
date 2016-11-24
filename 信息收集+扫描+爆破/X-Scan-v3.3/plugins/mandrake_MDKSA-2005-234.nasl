
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20465);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:234: sudo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:234 (sudo).");
 script_set_attribute(attribute: "description", value: "Charles Morris discovered a vulnerability in sudo versions prior to
1.6.8p12 where, when the perl taint flag is off, sudo does not clear
the PERLLIB, PERL5LIB, and PERL5OPT environment variables, which could
allow limited local users to cause a perl script to include and execute
arbitrary library files that have the same name as library files that
included by the script.
In addition, other environment variables have been included in the patch
that remove similar environment variables that could be used in python
and ruby, scripts, among others.
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:234");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-4158");
script_summary(english: "Check for the version of the sudo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sudo-1.6.8p1-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-2.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p8-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sudo-", release:"MDK10.1")
 || rpm_exists(rpm:"sudo-", release:"MDK10.2")
 || rpm_exists(rpm:"sudo-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4158", value:TRUE);
}
exit(0, "Host is not affected");
