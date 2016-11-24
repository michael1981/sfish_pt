
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18562);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:105: dbus");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:105 (dbus).");
 script_set_attribute(attribute: "description", value: "Dan Reed discovered a vulnerability in the D-BUS system for sending
messages between applications. He found that a user can send and
listen to messages on another user's per-user session bus if they
knew the address of the socket.
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:105");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0201");
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

if ( rpm_check( reference:"dbus-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-python-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dbus-x11-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-1_0-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-1_0-devel-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-glib-1_0-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdbus-qt-1_0-0.22-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dbus-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0201", value:TRUE);
}
exit(0, "Host is not affected");
