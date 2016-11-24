
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15601);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:121: netatalk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:121 (netatalk).");
 script_set_attribute(attribute: "description", value: "The etc2ps.sh script, part of the netatalk package, creates files in
/tmp with predicatable names which could allow a local attacker to use
symbolic links to point to a valid file on the filesystem which could
lead to the overwriting of arbitrary files if etc2ps.sh is executed
by someone with enough privilege.
The updated packages are patched to prevent this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:121");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0974");
script_summary(english: "Check for the version of the netatalk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"netatalk-1.6.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netatalk-devel-1.6.4-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netatalk-2.0-0beta2.3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netatalk-devel-2.0-0beta2.3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netatalk-1.6.3-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netatalk-devel-1.6.3-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"netatalk-", release:"MDK10.0")
 || rpm_exists(rpm:"netatalk-", release:"MDK10.1")
 || rpm_exists(rpm:"netatalk-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0974", value:TRUE);
}
exit(0, "Host is not affected");
