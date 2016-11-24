
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27275);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  java: SUN Java packages 1.4.2 update 13 (java-1_4_2-sun-2425)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-2425");
 script_set_attribute(attribute: "description", value: "The SUN Java packages have been upgraded to 1.4.2 update 13
to fix various security problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-2425");
script_end_attributes();

script_summary(english: "Check for the java-1_4_2-sun-2425 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2_update13-3.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
