
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(41406);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  java-1_6_0-ibm (2009-06-29)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-ibm");
 script_set_attribute(attribute: "description", value: "IBM Java 6 SR 5 was released fixing various bugs and
critical security issues:

CVE-2009-1093: A vulnerability in the Java Runtime
Environment (JRE) with initializing LDAP connections may be
exploited by a remote client to cause a denial-of-service
condition on the LDAP service.

CVE-2009-1094: A vulnerability in Java Runtime Environment
LDAP client implementation may allow malicious data from an
LDAP server to cause malicious code to be unexpectedly
loaded and executed on an LDAP client.

CVE-2009-1095 CVE-2009-1096: Buffer overflow
vulnerabilities in the Java Runtime Environment (JRE) with
unpacking applets and Java Web Start applications using the
unpack200 JAR unpacking utility may allow an untrusted
applet or application to escalate privileges. For example,
an untrusted applet may grant itself permissions to read
and write local files or execute local applications that
are accessible to the user running the untrusted applet.

CVE-2009-1097: A buffer overflow vulnerability in the Java
Runtime Environment with processing PNG images may allow an
untrusted Java Web Start application to escalate
privileges. For example, an untrusted application may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted application.

CVE-2009-1097: A buffer overflow vulnerability in the Java
Runtime Environment with processing GIF images may allow an
untrusted Java Web Start application to escalate
privileges. For example, an untrusted application may grant
itself permissions to read and write local files or execute
local applications that are accessible to the user running
the untrusted application.

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

CVE-2009-1100: A vulnerability in the Java Runtime
Environment (JRE) with storing temporary font files may
allow an untrusted applet or application to consume a
disproportionate amount of disk space resulting in a
denial-of-service condition.

CVE-2009-1100: A vulnerability in the Java Runtime
Environment (JRE) with processing temporary font files may
allow an untrusted applet or application to retain
temporary files resulting in a denial-of-service condition.

CVE-2009-1101: A vulnerability in the Java Runtime
Environment (JRE) HTTP server implementation may allow a
remote client to create a denial-of-service condition on a
JAX-WS service endpoint that runs on the JRE.

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

CVE-2009-1105: The Java Plug-in allows a trusted applet to
be launched on an earlier version of the Java Runtime
Environment (JRE) provided the user that downloaded the
applet allows it to run on the requested release. A
vulnerability allows Javascript code that is present in the
same web page as the applet to exploit known
vulnerabilities of the requested JRE.

CVE-2009-1106: A vulnerability in the Java Runtime
Environment with parsing crossdomain.xml files may allow an
untrusted applet to connect to any site that provides a
crossdomain.xml file instead of sites that allow the domain
that the applet is running on.

CVE-2009-1107: The Java Plugin displays a warning dialog
for signed applets. A signed applet can obscure the
contents of the dialog and trick a user into trusting the
applet.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-ibm");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=516361");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=494536");
script_end_attributes();

 script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");
script_summary(english: "Check for the java-1_6_0-ibm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_6_0-ibm-1.6.0-124.7.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-alsa-1.6.0-124.7.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-fonts-1.6.0-124.7.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-jdbc-1.6.0-124.7.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-plugin-1.6.0-124.7.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
