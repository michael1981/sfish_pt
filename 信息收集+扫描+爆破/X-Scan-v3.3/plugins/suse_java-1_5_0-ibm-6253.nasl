
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41528);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  Security update for IBM Java 5 (java-1_5_0-ibm-6253)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_5_0-ibm-6253");
 script_set_attribute(attribute: "description", value: "The update brings IBM Java 5 to SR9-SSU.

It fixes a lot of security issues: CVE-2009-1100: A
vulnerability in the Java Runtime Environment (JRE) with
storing temporary font files may allow an untrusted applet
or application to consume a disproportionate amount of disk
space resulting in a denial-of-service condition.

CVE-2009-1100: A vulnerability in the Java Runtime
Environment (JRE) with processing temporary font files may
allow an untrusted applet or application to retain
temporary files resulting in a denial-of-service condition.

CVE-2009-1103: A vulnerability in the Java Plug-in with
deserializing applets may allow an untrusted applet to
escalate privileges. For example, an untrusted applet may
grant itself permissions to read and write local files or
execute local applications that are accessible to the user
running the untrusted applet.

CVE-2009-1104: The Java Plug-in allows Javascript code that
is loaded from the localhost to connect to any port on the
system. This may be leveraged together with XSS
vulnerabilities in a blended attack to access other
applications listening on ports other than the one where
the Javascript code was served from.

CVE-2009-1093: A vulnerability in the Java Runtime
Environment (JRE) with initializing LDAP connections may be
exploited by a remote client to cause a denial-of-service
condition on the LDAP service.

CVE-2009-1094: A vulnerability in Java Runtime Environment
LDAP client implementation may allow malicious data from an
LDAP server to cause malicious code to be unexpectedly
loaded and executed on an LDAP client.

CVE-2009-1107: The Java Plugin displays a warning dialog
for signed applets. A signed applet can obscure the
contents of the dialog and trick a user into trusting the
applet.

CVE-2009-1095 CVE-2009-1096: Buffer overflow
vulnerabilities in the Java Runtime Environment (JRE) with
unpacking applets and Java Web Start applications using the
unpack200 JAR unpacking utility may allow an untrusted
applet or application to escalate privileges. For example,
an untrusted applet may grant itself permissions to read
and write local files or execute local applications that
are accessible to the user running the untrusted applet.

CVE-2009-1098: A buffer overflow vulnerability in the Java
Runtime Environment with processing GIF images may allow an
untrusted applet or Java Web Start application to escalate
privileges. For example, an untrusted applet may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted applet.

CVE-2009-1099: A buffer overflow vulnerability in the Java
Runtime Environment with processing fonts may allow an
untrusted applet or Java Web Start application to escalate
privileges. For example, an untrusted applet may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted applet.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_5_0-ibm-6253");
script_end_attributes();

script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1107");
script_summary(english: "Check for the java-1_5_0-ibm-6253 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_5_0-ibm-1.5.0_sr9-2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-alsa-1.5.0_sr9-2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-devel-1.5.0_sr9-2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-fonts-1.5.0_sr9-2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-jdbc-1.5.0_sr9-2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-ibm-plugin-1.5.0_sr9-2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
