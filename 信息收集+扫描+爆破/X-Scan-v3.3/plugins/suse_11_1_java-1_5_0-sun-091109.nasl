
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42460);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.1 Security Update:  java-1_5_0-sun (2009-11-09)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_5_0-sun");
 script_set_attribute(attribute: "description", value: "java-1_5_0-sun u22 update fixes the following security bugs:
- CVE-2009-3864: CVSS v2 Base Score: 7.5
- CVE-2009-3867: CVSS v2 Base Score: 9.3
- CVE-2009-3868: CVSS v2 Base Score: 9.3
- CVE-2009-3869: CVSS v2 Base Score: 9.3
- CVE-2009-3871: CVSS v2 Base Score: 9.3
- CVE-2009-3872: CVSS v2 Base Score: 10.0
- CVE-2009-3873: CVSS v2 Base Score: n/a
- CVE-2009-3874: CVSS v2 Base Score: 9.3
- CVE-2009-3875: CVSS v2 Base Score: 5.0
- CVE-2009-3876: CVSS v2 Base Score: 5.0
- CVE-2009-3877: CVSS v2 Base Score: 5.0 For bug details
  use the CVE-ID to query the Mitre database at
  http://cve.mitre.org/cve please.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_5_0-sun");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=552581");
script_end_attributes();

 script_cve_id("CVE-2009-3864", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");
script_summary(english: "Check for the java-1_5_0-sun package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-plugin-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update22-0.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
