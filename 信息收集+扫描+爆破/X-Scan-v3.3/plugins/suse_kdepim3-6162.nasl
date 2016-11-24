
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36710);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  kdepim3: KMail executes links in mail without confirmation (kdepim3-6162)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kdepim3-6162");
 script_set_attribute(attribute: "description", value: "This updates of KMail does not executes links in mail
without confirmation anymore.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kdepim3-6162");
script_end_attributes();

script_summary(english: "Check for the kdepim3-6162 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kdepim3-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdepim3-devel-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdepim3-kpilot-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdepim3-mobile-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdepim3-notes-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdepim3-time-management-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kitchensync-3.5.7.enterprise.0.20070904.708012-9.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
