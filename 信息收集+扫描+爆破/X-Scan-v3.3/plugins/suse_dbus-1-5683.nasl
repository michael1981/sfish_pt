
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34437);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  dbus-1: denial of service (dbus-1-5683)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch dbus-1-5683");
 script_set_attribute(attribute: "description", value: "This update fixes a denial of service bug in dbus.
(CVE-2008-3834)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch dbus-1-5683");
script_end_attributes();

script_cve_id("CVE-2008-3834");
script_summary(english: "Check for the dbus-1-5683 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"dbus-1-1.0.2-59.6", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"dbus-1-32bit-1.0.2-59.6", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"dbus-1-64bit-1.0.2-59.6", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"dbus-1-devel-1.0.2-59.6", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"dbus-1-devel-doc-1.0.2-59.6", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"dbus-1-x11-1.0.2-67.5", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
