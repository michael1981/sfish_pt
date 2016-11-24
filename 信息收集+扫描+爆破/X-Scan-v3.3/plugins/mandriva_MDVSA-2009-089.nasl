
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36781);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:089: opensc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:089 (opensc).");
 script_set_attribute(attribute: "description", value: "OpenSC before 0.11.7 allows physically proximate attackers to bypass
intended PIN requirements and read private data objects via a (1) low
level APDU command or (2) debugging tool, as demonstrated by reading
the 4601 or 4701 file with the opensc-explorer or opensc-tool program.
The updated packages fix the issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:089");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0368");
script_summary(english: "Check for the version of the opensc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libopensc2-0.11.3-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc-devel-0.11.3-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-plugin-opensc-0.11.3-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opensc-0.11.3-2.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc2-0.11.3-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc-devel-0.11.3-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-plugin-opensc-0.11.3-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opensc-0.11.3-2.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc2-0.11.7-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc-devel-0.11.7-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-plugin-opensc-0.11.7-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opensc-0.11.7-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"opensc-", release:"MDK2008.0")
 || rpm_exists(rpm:"opensc-", release:"MDK2008.1")
 || rpm_exists(rpm:"opensc-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0368", value:TRUE);
}
exit(0, "Host is not affected");
