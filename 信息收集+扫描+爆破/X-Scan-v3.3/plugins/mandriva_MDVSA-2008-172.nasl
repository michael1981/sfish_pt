
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36594);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:172: amarok");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:172 (amarok).");
 script_set_attribute(attribute: "description", value: "A flaw in Amarok prior to 1.4.10 would allow local users to overwrite
arbitrary files via a symlink attack on a temporary file that Amarok
created with a predictable name (CVE-2008-3699).
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:172");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3699");
script_summary(english: "Check for the version of the amarok package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"amarok-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-engine-xine-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-scripts-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok0-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok0-scripts-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok-devel-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok-scripts-devel-1.4.7-9.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-engine-void-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-engine-xine-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-engine-yauap-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"amarok-scripts-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok0-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok0-scripts-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok-devel-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libamarok-scripts-devel-1.4.8-12.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"amarok-", release:"MDK2008.0")
 || rpm_exists(rpm:"amarok-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3699", value:TRUE);
}
exit(0, "Host is not affected");
