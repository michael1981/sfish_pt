
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29474);
 script_version ("$Revision: 1.10 $");
 script_name(english: "SuSE Security Update:  Security update for Java (java-1_5_0-ibm-3891)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_5_0-ibm-3891");
 script_set_attribute(attribute: "description", value: "The IBM Java JRE/SDK has been brought to release 1.4.2 SR8,
containing several bugfixes, including the following
security fixes:

CVE-2007-0243: A buffer overflow vulnerability in the
Java(TM) Runtime Environment may allow an untrusted applet
to elevate its privileges. For example, an applet may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted applet.

CVE-2006-6737/CVE-2006-6736: Two vulnerabilities in the
Java Runtime Environment may independently allow an
untrusted applet to access data in other applets.

CVE-2006-6745: Two vulnerabilities in the Java(TM) Runtime
Environment with serialization may independently allow an
untrusted applet or application to elevate its privileges.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_5_0-ibm-3891");
script_end_attributes();

script_cve_id("CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745", "CVE-2007-0243");
script_summary(english: "Check for the java-1_5_0-ibm-3891 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr5-1.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr5-1.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr5-1.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr5-1.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr5-1.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-demo-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-src-1.5.0_sr5-1.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
