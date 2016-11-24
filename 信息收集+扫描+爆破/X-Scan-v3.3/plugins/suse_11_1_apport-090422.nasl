
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40189);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.1 Security Update:  apport (2009-04-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for apport");
 script_set_attribute(attribute: "description", value: "The apport crash watcher / handler suite contains a cron
job that cleanes the world writeable /var/crash directory
unsafely, allowing local attackers to remove random files
on the system. (CVE-2009-1295)

This update fixes this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for apport");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=495053");
script_end_attributes();

 script_cve_id("CVE-2009-1295");
script_summary(english: "Check for the apport package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apport-0.114-8.6.1", release:"SUSE11.1", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-0.114-8.6.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-crashdb-opensuse-0.114-8.6.1", release:"SUSE11.1", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-crashdb-opensuse-0.114-8.6.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-gtk-0.114-8.6.1", release:"SUSE11.1", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-gtk-0.114-8.6.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-qt-0.114-8.6.1", release:"SUSE11.1", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-qt-0.114-8.6.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-retrace-0.114-8.6.1", release:"SUSE11.1", cpu:"i586") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"apport-retrace-0.114-8.6.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_note(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
