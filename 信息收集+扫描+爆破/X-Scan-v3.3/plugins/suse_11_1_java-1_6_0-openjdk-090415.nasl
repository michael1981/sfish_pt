
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40240);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  java-1_6_0-openjdk (2009-04-15)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-openjdk");
 script_set_attribute(attribute: "description", value: "This update fixes an integer overflow in the
PulseAudioTargetDataL class. (CVE-2009-0794)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-openjdk");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=493146");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=492555");
script_end_attributes();

 script_cve_id("CVE-2009-0794");
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
if ( rpm_check( reference:"java-1_6_0-openjdk-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-demo-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-demo-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-devel-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-devel-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-javadoc-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-javadoc-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-plugin-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-plugin-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-src-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-openjdk-src-1.4_b14-24.4.3", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
