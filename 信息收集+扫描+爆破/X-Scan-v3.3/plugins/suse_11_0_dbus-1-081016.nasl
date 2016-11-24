
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39947);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  dbus-1 (2008-10-16)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for dbus-1");
 script_set_attribute(attribute: "description", value: "This update fixes a denial of service bug in dbus.
(CVE-2008-3834)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for dbus-1");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=432901");
script_end_attributes();

 script_cve_id("CVE-2008-3834");
script_summary(english: "Check for the dbus-1 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"dbus-1-1.2.1-15.2", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-1.2.1-15.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-32bit-1.2.1-15.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-devel-1.2.1-15.2", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-devel-1.2.1-15.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-devel-doc-1.2.1-15.2", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-devel-doc-1.2.1-15.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-x11-1.2.1-18.2", release:"SUSE11.0", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-x11-1.2.1-18.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
