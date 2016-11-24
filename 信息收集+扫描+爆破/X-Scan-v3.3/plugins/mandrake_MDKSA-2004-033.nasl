
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14132);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:033: xine-ui");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:033 (xine-ui).");
 script_set_attribute(attribute: "description", value: "Shaun Colley discovered a temporary file vulnerability in the
xine-check script packaged in xine-ui. This problem could allow
local attackers to overwrite arbitrary files with the privileges
of the user invoking the script.
The updated packages change the location of where temporary files are
written to prevent this attack.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:033");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0372");
script_summary(english: "Check for the version of the xine-ui package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xine-ui-0.9.23-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-aa-0.9.23-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-fb-0.9.23-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-0.9.22-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-aa-0.9.22-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xine-ui-fb-0.9.22-5.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xine-ui-", release:"MDK10.0")
 || rpm_exists(rpm:"xine-ui-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0372", value:TRUE);
}
exit(0, "Host is not affected");
