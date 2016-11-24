
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
 script_id(42396);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  java-1_6_0-ibm (2009-11-02)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-ibm");
 script_set_attribute(attribute: "description", value: "The IBM Java 6 JRE/SDK was updated to Service Release 6,
fixing various bugs and security issues.

Following security issues were fixed: CVE-2009-2676: A
security vulnerability in the JNLPAppletLauncher might
impact users of the Sun JDK and JRE. Non-current versions
of the JNLPAppletLauncher might be re-purposed with an
untrusted Java applet to write arbitrary files on the
system of the user downloading and running the untrusted
applet.

The JNLPAppletLauncher is a general purpose JNLP-based
applet launcher class for deploying applets that use
extension libraries containing native code.

CVE-2009-2493: The Java Runtime Environment includes the
Java Web Start technology that uses the Java Web Start
ActiveX control to launch Java Web Start in Internet
Explorer. A security vulnerability in the Active Template
Library (ATL) in various releases of Microsoft Visual
Studio, which is used by the Java Web Start ActiveX
control, might allow the Java Web Start ActiveX control to
be leveraged to run arbitrary code. This might occur as the
result of a user of the Java Runtime Environment viewing a
specially crafted web page that exploits this vulnerability.

CVE-2009-2670: A vulnerability in the Java Runtime
Environment audio system might allow an untrusted applet or
Java Web Start application to access system properties.

CVE-2009-0217: A vulnerability with verifying HMAC-based
XML digital signatures in the XML Digital Signature
implementation included with the Java Runtime Environment
(JRE) might allow authentication to be bypassed.
Applications that validate HMAC-based XML digital
signatures might be vulnerable to this type of attack.

Note: This vulnerability cannot be exploited by an
untrusted applet or Java Web Start application. 

CVE-2009-2671 CVE-2009-2672: A vulnerability in the Java
Runtime Environment with the SOCKS proxy implementation
might allow an untrusted applet or Java Web Start
application to determine the username of the user running
the applet or application.

A second vulnerability in the Java Runtime Environment with
the proxy mechanism implementation might allow an untrusted
applet or Java Web Start application to obtain browser
cookies and leverage those cookies to hijack sessions.

CVE-2009-2673: A vulnerability in the Java Runtime
Environment with the proxy mechanism implementation might
allow an untrusted applet or Java Web Start application to
make non-authorized socket or URL connections to hosts
other than the origin host.

CVE-2009-2674: An integer overflow vulnerability in the
Java Runtime Environment with processing JPEG images might
allow an untrusted Java Web Start application to escalate
privileges. For example, an untrusted application might
grant itself permissions to read and write local files or
run local applications that are accessible to the user
running the untrusted applet.

CVE-2009-2675: An integer overflow vulnerability in the
Java Runtime Environment with unpacking applets and Java
Web Start applications using the unpack200 JAR unpacking
utility might allow an untrusted applet or application to
escalate privileges. For example, an untrusted applet might
grant itself permissions to read and write local files or
run local applications that are accessible to the user
running the untrusted applet.

CVE-2009-2625: A vulnerability in the Java Runtime
Environment (JRE) with parsing XML data might allow a
remote client to create a denial-of-service condition on
the system that the JRE runs on.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-ibm");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=548655");
script_end_attributes();

 script_cve_id("CVE-2009-0217", "CVE-2009-2493", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676");
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
if ( rpm_check( reference:"java-1_6_0-ibm-1.6.0_sr6-1.1.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-alsa-1.6.0_sr6-1.1.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-fonts-1.6.0_sr6-1.1.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-jdbc-1.6.0_sr6-1.1.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-ibm-plugin-1.6.0_sr6-1.1.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
