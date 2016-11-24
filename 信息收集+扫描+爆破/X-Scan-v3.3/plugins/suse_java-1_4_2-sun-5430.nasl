
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34035);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  java-1_4_2-sun: Security update to 1.4.2 patchlevel 18 (java-1_4_2-sun-5430)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-5430");
 script_set_attribute(attribute: "description", value: "Sun Java was updated to 1.4.2u18 to fix following security
vulnerabilities:

CVE-2008-3114: Unspecified vulnerability in Sun Java Web
Start in JDK and JRE 6 before Update 7, JDK and JRE 5.0
before Update 16, and SDK and JRE 1.4.x before 1.4.2_18
allows context-dependent attackers to obtain sensitive
information (the cache location) via an untrusted
application, aka CR 6704074. 

CVE-2008-3113: Unspecified vulnerability in Sun Java Web
Start in JDK and JRE 5.0 before Update 16 and SDK and JRE
1.4.x before 1.4.2_18 allows remote attackers to create or
delete arbitrary files via an untrusted application, aka CR
6704077. 

CVE-2008-3112: Unspecified vulnerability in Sun Java Web
Start in JDK and JRE 6 before Update 7, JDK and JRE 5.0
before Update 16, and SDK and JRE 1.4.x before 1.4.2_18
allows remote attackers to create arbitrary files via an
untrusted application, aka CR 6703909. 

CVE-2008-3111: Multiple buffer overflows in Sun Java Web
Start in JDK and JRE 6 before Update 4, JDK and JRE 5.0
before Update 16, and SDK and JRE 1.4.x before 1.4.2_18
allow context-dependent attackers to gain privileges via an
untrusted application, as demonstrated by an application
that grants itself privileges to (1) read local files, (2)
write to local files, or (3) execute local programs, aka CR
6557220.

CVE-2008-3108:  Buffer overflow in Sun Java Runtime
Environment (JRE) in JDK and JRE 5.0 before Update 10, SDK
and JRE 1.4.x before 1.4.2_18, and SDK and JRE 1.3.x before
1.3.1_23 allows context-dependent attackers to gain
privileges via unspecified vectors related to font
processing. 

CVE-2008-3107: Unspecified vulnerability in the Virtual
Machine in Sun Java Runtime Environment (JRE) in JDK and
JRE 6 before Update 7, JDK and JRE 5.0 before Update 16,
and SDK and JRE 1.4.x before 1.4.2_18 allows
context-dependent attackers to gain privileges via an
untrusted (1) application or (2) applet, as demonstrated by
an application or applet that grants itself privileges to
(a) read local files, (b) write to local files, or (c)
execute local programs.

CVE-2008-3104: Multiple unspecified vulnerabilities in Sun
Java Runtime Environment (JRE) in JDK and JRE 6 before
Update 7, JDK and JRE 5.0 before Update 16, SDK and JRE
1.4.x before 1.4.2_18, and SDK and JRE 1.3.x before
1.3.1_23 allow remote attackers to violate the security
model for an applet's outbound connections by connecting to
localhost services running on the machine that loaded the
applet.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-5430");
script_end_attributes();

script_cve_id("CVE-2008-3114", "CVE-2008-3113", "CVE-2008-3112", "CVE-2008-3111", "CVE-2008-3108", "CVE-2008-3107", "CVE-2008-3104");
script_summary(english: "Check for the java-1_4_2-sun-5430 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2_update18-0.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
