
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41623);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE 11.1 Security Update:  java-1_6_0-openjdk (2009-09-22)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-openjdk");
 script_set_attribute(attribute: "description", value: "This update of java-1_6_0-openjdk fixes the following
issues:
- CVE-2009-2670: OpenJDK Untrusted applet System properties
  access
- CVE-2009-2671,CVE-2009-2672: OpenJDK Proxy mechanism
  information leaks
- CVE-2009-2673: OpenJDK proxy mechanism allows
  non-authorized socket connections
- CVE-2009-2674: Java Web Start Buffer JPEG processing
  integer overflow
- CVE-2009-2675: Java Web Start Buffer unpack200 processing
  integer overflow
- CVE-2009-2625: OpenJDK XML parsing Denial-Of-Service
- CVE-2009-2475: OpenJDK information leaks in mutable
  variables
- CVE-2009-2476: OpenJDK OpenType checks can be bypassed
- CVE-2009-2689: OpenJDK JDK13Services grants unnecessary
  privileges
- CVE-2009-2690: OpenJDK private variable information
  disclosure
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-openjdk");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=537969");
script_end_attributes();

 script_cve_id("CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690");
script_summary(english: "Check for the java-1_6_0-openjdk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_6_0-openjdk-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-demo-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-demo-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-devel-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-devel-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-javadoc-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-javadoc-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-plugin-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-plugin-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-src-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-src-1.6_b16-0.1.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
