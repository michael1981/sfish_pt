
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40167);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  ModemManager (2009-02-26)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for ModemManager");
 script_set_attribute(attribute: "description", value: "The NetworkManager configuration was too permissive and
allowed any user to read secrets (CVE-2009-0365) or
manipulate the configuration of other users (CVE-2009-0578).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for ModemManager");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478080");
script_end_attributes();

 script_cve_id("CVE-2009-0365", "CVE-2009-0578");
script_summary(english: "Check for the ModemManager package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ModemManager-0.1_20081203-6.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ModemManager-0.1_20081203-6.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-devel-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-devel-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-doc-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-doc-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-glib-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"NetworkManager-glib-0.7.0.r4359-15.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
