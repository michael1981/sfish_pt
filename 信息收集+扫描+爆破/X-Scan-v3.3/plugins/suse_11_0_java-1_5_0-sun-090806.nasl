
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40524);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.0 Security Update:  java-1_5_0-sun (2009-08-06)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_5_0-sun");
 script_set_attribute(attribute: "description", value: "The Sun Java JRE /JDK 5 was updated to Update 20 fixing
various security issues.

CVE-2009-2670: The audio system in Sun Java Runtime
Environment (JRE) in JDK and JRE 6 before Update 15, and
JDK and JRE 5.0 before Update 20, does not prevent access
to java.lang.System properties by (1) untrusted applets and
(2) Java Web Start applications, which allows
context-dependent attackers to obtain sensitive information
by reading these properties.

CVE-2009-2671: The SOCKS proxy implementation in Sun Java
Runtime Environment (JRE) in JDK and JRE 6 before Update
15, and JDK and JRE 5.0 before Update 20, allows remote
attackers to discover the username of the account that
invoked an untrusted (1) applet or (2) Java Web Start
application via unspecified vectors.

CVE-2009-2672: The proxy mechanism implementation in Sun
Java Runtime Environment (JRE) in JDK and JRE 6 before
Update 15, and JDK and JRE 5.0 before Update 20, does not
prevent access to browser cookies by untrusted (1) applets
and (2) Java Web Start applications, which allows remote
attackers to hijack web sessions via unspecified vectors.

CVE-2009-2673: The proxy mechanism implementation in Sun
Java Runtime Environment (JRE) in JDK and JRE 6 before
Update 15, and JDK and JRE 5.0 before Update 20, allows
remote attackers to bypass intended access restrictions and
connect to arbitrary sites via unspecified vectors, related
to a declaration that lacks the final keyword.

CVE-2009-2674: Integer overflow in Sun Java Runtime
Environment (JRE) in JDK and JRE 6 before Update 15 allows
context-dependent attackers to gain privileges via vectors
involving an untrusted Java Web Start application that
grants permissions to itself, related to parsing of JPEG
images.

CVE-2009-2675: Integer overflow in the unpack200 utility in
Sun Java Runtime Environment (JRE) in JDK and JRE 6 before
Update 15, and JDK and JRE 5.0 before Update 20, allows
context-dependent attackers to gain privileges via vectors
involving an untrusted (1) applet or (2) Java Web Start
application that grants permissions to itself, related to
decompression.

CVE-2009-2676: Unspecified vulnerability in
JNLPAppletlauncher in Sun Java SE, and SE for Business, in
JDK and JRE 6 Update 14 and earlier +and JDK and JRE 5.0
Update 19 and earlier; and Java SE for Business in SDK and
JRE 1.4.2_21 and earlier; allows remote attackers to create
or modify arbitrary files via vectors involving an
untrusted Java applet.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_5_0-sun");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=528268");
script_end_attributes();

 script_cve_id("CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676");
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
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-alsa-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-demo-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-devel-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-jdbc-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-plugin-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_5_0-sun-src-1.5.0_update20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
