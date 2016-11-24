
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
 script_id(42853);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.1 Security Update:  java-1_6_0-sun (2009-11-13)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for java-1_6_0-sun");
 script_set_attribute(attribute: "description", value: "The Sun Java 6 SDK/JRE was updated to u17 update fixing
bugs and various security issues:

CVE-2009-3866:The Java Web Start Installer in Sun Java SE
in JDK and JRE 6 before Update 17 does not properly use
security model permissions when removing installer
extensions, which allows remote attackers to execute
arbitrary code by modifying a certain JNLP file to have a
URL field that poi nts to an unintended trusted
application, aka Bug Id 6872824.

CVE-2009-3867: Stack-based buffer overflow in the
HsbParser.getSoundBank function in Sun Java SE in JDK and
JRE 5.0 before Update 22, JDK and JRE 6 before Update 17,
SDK and JRE 1.3.x before 1.3.1_27, and SDK and JRE 1.4.x
before 1.4.2_24 allows remote attackers to execute
arbitrary code via a long file: URL in an argument, aka Bug
Id 6854303.

CVE-2009-3869: Stack-based buffer overflow in the
setDiffICM function in the Abstract Window Toolkit (AWT) in
Java Runtime Environment (JRE) in Sun Java SE in JDK and
JRE 5.0 before Update 22, JDK and JRE 6 before Update 17,
SDK and JRE 1.3.x before 1.3.1_27, and SDK and JRE 1.4.x
before 1.4.2_ 24 allows remote attackers to execute
arbitrary code via a crafted argument, aka Bug Id 6872357.

CVE-2009-3871: Heap-based buffer overflow in the
setBytePixels function in the Abstract Window Toolkit (AWT)
in Java Runtime Environment (JRE) in Sun Java SE in JDK and
JRE 5.0 before Update 22, JDK and JRE 6 before Update 17,
SDK and JRE 1.3.x before 1.3.1_27, and SDK and JRE 1.4.x
before 1.4. 2_24 allows remote attackers to execute
arbitrary code via crafted arguments, aka Bug Id 6872358.

CVE-2009-3874: Integer overflow in the JPEGImageReader
implementation in the ImageI/O component in Sun Java SE in
JDK and JRE 5.0 before Update 22, JDK and JRE 6 before
Update 17, and SDK and JRE 1.4.x before 1.4.2_24 allows
remote attackers to execute arbitrary code via large
subsample dimensi ons in a JPEG file that triggers a
heap-based buffer overflow, aka Bug Id 6874643.

CVE-2009-3875: The MessageDigest.isEqual function in Java
Runtime Environment (JRE) in Sun Java SE in JDK and JRE 5.0
before Update 22, JDK and JRE 6 befor e Update 17, SDK and
JRE 1.3.x before 1.3.1_27, and SDK and JRE 1.4.x before
1.4.2_24 allows remote attackers to spoof HMAC-based
digital si gnatures, and possibly bypass authentication,
via unspecified vectors related to 'timing attack
vulnerabilities,' aka Bug Id 6863503.

CVE-2009-3876: Unspecified vulnerability in Sun Java SE in
JDK and JRE 5.0 before Update 22, JDK and JRE 6 before
Update 17, SDK and JRE 1.3.x before 1.3.1 _27, and SDK and
JRE 1.4.x before 1.4.2_24 allows remote attackers to cause
a denial of service (memory consumption) via crafted DER
encoded data, which is not properly decoded by the ASN.1
DER input stream parser, aka Bug Id 6864911.

CVE-2009-3877: Unspecified vulnerability in Sun Java SE in
JDK and JRE 5.0 before Update 22, JDK and JRE 6 before
Update 17, SDK and JRE 1.3.x before 1.3.1 _27, and SDK and
JRE 1.4.x before 1.4.2_24 allows remote attackers to cause
a denial of service (memory consumption) via crafted HTTP
header s, which are not properly parsed by the ASN.1 DER
input stream parser, aka Bug Id 6864911.

CVE-2009-3864: The Java Update functionality in Java
Runtime Environment (JRE) in Sun Java SE in JDK and JRE 5.0
before Update 22 and JDK and JRE 6 before Update 17, when a
non-English version of Windows is used, does not retrieve
available new JRE versions, which allows remote attackers
to lev erage vulnerabilities in older releases of this
software, aka Bug Id 6869694.

CVE-2009-3865: The launch method in the Deployment Toolkit
plugin in Java Runtime Environment (JRE) in Sun Java SE in
JDK and JRE 6 before Update 17 allows remote attackers to
execute arbitrary commands via a crafted web page, aka Bug
Id 6869752.

CVE-2009-3868: Sun Java SE in JDK and JRE 5.0 before Update
22, JDK and JRE 6 before Update 17, SDK and JRE 1.3.x
before 1.3.1_27, and SDK and JRE 1.4.x be fore 1.4.2_24
does not properly parse color profiles, which allows remote
attackers to gain privileges via a crafted image file, aka
Bug Id 6862970.

CVE-2009-3872: Unspecified vulnerability in the JPEG JFIF
Decoder in Sun Java SE in JDK and JRE 5.0 before Update 22,
JDK and JRE 6 before Update 17, SDK a nd JRE 1.3.x before
1.3.1_27, and SDK and JRE 1.4.x before 1.4.2_24 allows
remote attackers to gain privileges via a crafted image
file, aka Bug Id 6862969.

CVE-2009-3873: The JPEG Image Writer in Sun Java SE in JDK
and JRE 5.0 before Update 22, JDK and JRE 6 before Update
17, and SDK and JRE 1.4.x before 1.4.2 _24 allows remote
attackers to gain privileges via a crafted image file,
related to a 'quanization problem,' aka Bug Id 6862968.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for java-1_6_0-sun");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=552586");
script_end_attributes();

 script_cve_id("CVE-2009-3864", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");
script_summary(english: "Check for the java-1_6_0-sun package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_6_0-sun-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-alsa-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-alsa-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-devel-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-devel-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-jdbc-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-jdbc-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-plugin-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-plugin-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-src-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"java-1_6_0-sun-src-1.6.0.u17-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
