
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27278);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  SUN Java packages prior 1.5.0 update 7 allow DOS. (java-1_5_0-sun-1438)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_5_0-sun-1438");
 script_set_attribute(attribute: "description", value: "Sun Java Runtime Environment (JRE) 1.5.0_6 and earlier, JDK 
1.5.0_6 and earlier, and SDK 1.5.0_6 and earlier allows 
remote attackers to cause a denial of service (disk 
consumption) by using the Font.createFont function to 
create temporary files of arbitrary size in the %temp% 
directory (CVE-2006-2426). 
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_5_0-sun-1438");
script_end_attributes();

script_cve_id("CVE-2006-2426");
script_summary(english: "Check for the java-1_5_0-sun-1438 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-plugin-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_07-1.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
