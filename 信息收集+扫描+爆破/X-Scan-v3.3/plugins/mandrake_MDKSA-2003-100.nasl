
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14082);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:100: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:100 (gdm).");
 script_set_attribute(attribute: "description", value: "Two vulnerabilities were discovered in gdm by Jarno Gassenbauer that
would allow a local attacker to cause gdm to crash or freeze.
The provided packages are patched to fix this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:100");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0793", "CVE-2003-0794");
script_summary(english: "Check for the version of the gdm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gdm-2.4.1.6-0.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.1.6-0.4.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-2.4.4.0-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.4.0-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gdm-", release:"MDK9.1")
 || rpm_exists(rpm:"gdm-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0793", value:TRUE);
 set_kb_item(name:"CVE-2003-0794", value:TRUE);
}
exit(0, "Host is not affected");
