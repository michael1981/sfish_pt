
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30195);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  java-1_5_0-sun: Security update to 1.5.0 u14 (java-1_5_0-sun-4940)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_5_0-sun-4940");
 script_set_attribute(attribute: "description", value: "This security update brings SUN Java 1.5.0 to update14. The
security issues fixed are not yset publically known, but it
fixes several ones.

It also contains timezone update 2007k.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_5_0-sun-4940");
script_end_attributes();

script_summary(english: "Check for the java-1_5_0-sun-4940 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-plugin-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update14-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
