
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42046);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:256: dbus");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:256 (dbus).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered and corrected in dbus:
The _dbus_validate_signature_with_reason function
(dbus-marshal-validate.c) in D-Bus (aka DBus) uses incorrect logic
to validate a basic type, which allows remote attackers to spoof a
signature via a crafted key. NOTE: this is due to an incorrect fix
for CVE-2008-3834 (CVE-2009-1189).
This update provides a fix for this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:256");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3834", "CVE-2009-1189");
script_summary(english: "Check for the version of the dbus package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dbus-1.1.20-5.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-1.1.20-5.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-1_3-1.1.20-5.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-1-devel-1.1.20-5.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-1.2.3-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-1.2.3-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-1_3-1.2.3-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-1-devel-1.2.3-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dbus-", release:"MDK2008.1")
 || rpm_exists(rpm:"dbus-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-3834", value:TRUE);
 set_kb_item(name:"CVE-2009-1189", value:TRUE);
}
exit(0, "Host is not affected");
