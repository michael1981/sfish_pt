
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(29473);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Sun Java 1.4.2 (java-1_4_2-sun-4533)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-4533");
 script_set_attribute(attribute: "description", value: "The Sun JAVA JDK 1.4.2 was upgraded to release 16 to fix
various bugs, including the following security bugs:

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103
079-1

CVE-2007-5232: Sun Java Runtime Environment (JRE) in JDK
and JRE 6 Update 2 and earlier, JDK and JRE 5.0 Update 12
and earlier, SDK and JRE 1.4.2_15 and earlier, and SDK and
JRE 1.3.1_20 and earlier, when applet caching is enabled,
allows remote attackers to violate the security model for
an applet's outbound connections via a DNS rebinding attack.

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103
073-1

CVE-2007-5236: Java Web Start in Sun JDK and JRE 5.0 Update
12 and earlier, and SDK and JRE 1.4.2_15 and earlier, on
Windows does not properly enfor ce access restrictions for
untrusted applications, which allows user-assisted remote
attackers to read local files via an untrusted applica tion.

CVE-2007-5237: Java Web Start in Sun JDK and JRE 6 Update 2
and earlier does not properly enforce access restrictions
for untrusted applications, which allows user-assisted
remote attackers to read and modify local files via an
untrusted application, aka 'two vulnerabilities'.

CVE-2007-5238: Java Web Start in Sun JDK and JRE 6 Update 2
and earlier, JDK and JRE 5.0 Update 12 and earlier, and SDK
and JRE 1.4.2_15 and earlier does not properly enforce
access restrictions for untrusted applications, which
allows user-assisted remote attackers to obtain sensitive
information (the Java Web Start cache location) via an
untrusted application, aka 'three vulnerabilities.'

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103
072-1

CVE-2007-5239: Java Web Start in Sun JDK and JRE 6 Update 2
and earlier, JDK and JRE 5.0 Update 12 and earlier, SDK and
JRE 1.4.2_15 and earlier, and SDK and JRE 1.3.1_20 and
earlier does not properly enforce access restrictions for
untrusted (1) applications and (2) applets, which allows
user-assisted remote attackers to copy or rename arbitrary
files when local users perform drag-and-drop operations
from the untrusted application or applet window onto
certain types of desktop applications.

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103
071-1

CVE-2007-5240: Visual truncation vulnerability in the Java
Runtime Environment in Sun JDK and JRE 6 Update 2 and
earlier, JDK and JRE 5.0 Update 12 and earlier, SDK and JRE
1.4.2_15 and earlier, and SDK and JRE 1.3.1_20 and earlier
allows remote attackers to circumvent display of the
untrusted-code warning banner by creating a window larger
than the workstation screen.

http://sunsolve.sun.com/search/document.do?assetkey=1-26-103
078-1

CVE-2007-5273: Sun Java Runtime Environment (JRE) in JDK
and JRE 6 Update 2 and earlier, JDK and JRE 5.0 Update 12
and earlier, SDK and JRE 1.4.2_15 and earlier, and SDK and
JRE 1.3.1_20 and earlier, when an HTTP proxy server is
used, allows remote attackers to violate the security model
for an applet's outbound connections via a multi-pin DNS
rebinding attack in which the applet download relies on DNS
resolution on the proxy server, but the applet's socket
operations rely on DNS resolution on the local machine, a
different issue than CVE-2007-5274.

CVE-2007-5274: Sun Java Runtime Environment (JRE) in JDK
and JRE 6 Update 2 and earlier, JDK and JRE 5.0 Update 12
and earlier, SDK and JRE 1.4.2_15 and earlier, and SDK and
JRE 1.3.1_20 and earlier, when Firefox or Opera is used,
allows remote attackers to violate the security model for
JavaScript outbound connections via a multi-pin DNS
rebinding attack dependent on the LiveConnect API, in which
JavaScript download relies on DNS resolution by the
browser, but JavaScript socket operations rely on separate
DNS resolution by a Java Virtual Machine (JVM), a different
issue than CVE-2007-5273.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-4533");
script_end_attributes();

script_cve_id("CVE-2007-5232", "CVE-2007-5236", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274");
script_summary(english: "Check for the java-1_4_2-sun-4533 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.16-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.16-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.16-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.16-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.16-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.16-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
