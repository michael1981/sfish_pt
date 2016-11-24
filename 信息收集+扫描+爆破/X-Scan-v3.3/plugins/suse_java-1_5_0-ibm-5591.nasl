
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34200);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for IBM Java 1.5 (java-1_5_0-ibm-5591)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_5_0-ibm-5591");
 script_set_attribute(attribute: "description", value: "IBM Java 5 was updated to SR8 to fix various security
issues:

CVE-2008-3104: Multiple vulnerabilities with unsigned
applets were reported. A remote attacker could misuse an
unsigned applet to connect to localhost services running on
the host running the applet.

CVE-2008-3106: A vulnerability in the XML processing API
was found. A remote attacker who caused malicious XML to be
processed by an untrusted applet or application was able to
elevate permissions to access URLs on a remote host.

CVE-2008-3108: A buffer overflow vulnerability was found in
the font processing code. This allowed remote attackers to
extend the permissions of an untrusted applet or
application, allowing it to read and/or write local files,
as well as to execute local applications accessible to the
user running the untrusted application.

CVE-2008-3111: Several buffer overflow vulnerabilities in
Java Web Start were reported.  These vulnerabilities
allowed an untrusted Java Web Start application to elevate
its privileges, allowing it to read and/or write local
files, as well as to execute local applications accessible
to the user running the untrusted application.

CVE-2008-3112, CVE-2008-3113: Two file processing
vulnerabilities in Java Web Start were found. A remote
attacker, by means of an untrusted Java Web Start
application, was able to create or delete arbitrary files
with the permissions of the user running the untrusted
application.

CVE-2008-3114: A vulnerability in Java Web Start when
processing untrusted applications was reported. An attacker
was able to acquire sensitive information, such as the
cache location.

This release also reinstates previous Crypto Export policy
jars lost between SR3 and SR8.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_5_0-ibm-5591");
script_end_attributes();

script_cve_id("CVE-2008-3104", "CVE-2008-3106", "CVE-2008-3108", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114");
script_summary(english: "Check for the java-1_5_0-ibm-5591 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-fonts-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-fonts-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-demo-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-src-1.5.0_sr8-1.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
