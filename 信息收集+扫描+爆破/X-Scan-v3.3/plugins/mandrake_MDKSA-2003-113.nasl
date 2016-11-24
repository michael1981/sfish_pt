
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14095);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:113: screen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:113 (screen).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered and fixed in screen by Timo Sirainen
who found an exploitable buffer overflow that allowed privilege
escalation. This vulnerability also has the potential to allow
attackers to gain control of another user's screen session. The
ability to exploit is not trivial and requires approximately 2GB
of data to be transferred in order to do so.
Updated packages are available that fix the vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:113");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0972");
script_summary(english: "Check for the version of the screen package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"screen-3.9.11-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"screen-3.9.13-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"screen-3.9.15-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"screen-", release:"MDK9.0")
 || rpm_exists(rpm:"screen-", release:"MDK9.1")
 || rpm_exists(rpm:"screen-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0972", value:TRUE);
}
exit(0, "Host is not affected");
