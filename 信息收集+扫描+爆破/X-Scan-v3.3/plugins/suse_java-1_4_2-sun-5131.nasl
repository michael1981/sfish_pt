
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31772);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Sun Java (java-1_4_2-sun-5131)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-5131");
 script_set_attribute(attribute: "description", value: "Sun Java was updated to 1.4.2u17 to fix following security
vulnerabilities:

- CVE-2008-1158: Unspecified vulnerability in the Virtual
  Machine for Sun Java Runtime Environment (JRE) and JDK 6
  Update 4 and earlier, 5.0 Update 14 and earlier, and
  SDK/JRE 1.4.2_16 and earlier allows remote attackers
  should gain privileges via an untrusted application or
  applet, a different issue than CVE-2008-1186.
- CVE-2008-1186: Unspecified vulnerability in the Virtual
  Machine for Sun Java Runtime Environment (JRE) and JDK
  5.0 Update 13 and earlier, and SDK/JRE 1.4.2_16 and
  earlier, allows remote attackers to gain privileges via
  an untrusted application or applet, a different issue
  than CVE-2008-1185.
- CVE-2008-1187: Unspecified vulnerability in Sun Java
  Runtime Environment (JRE) and JDK 6 Update 4 and earlier,
  5.0 Update 14 and earlier, and SDK/JRE 1.4.2_16 and
  earlier allows remote attackers to cause a denial of
  service (JRE crash) and possibly execute arbitrary code
  via unknown vectors related to XSLT transforms.
- CVE-2008-1189: Buffer overflow in Java Web Start in Sun
  JDK and JRE 6 Update 4 and earlier, 5.0 Update 14 and
  earlier, and SDK/JRE 1.4.2_16 and earlier allows remote
  attackers to execute arbitrary code via unknown vectors,
  a different issue than CVE-2008-1188.
- CVE-2008-1190: Unspecified vulnerability in Java Web
  Start in Sun JDK and JRE 6 Update 4 and earlier, 5.0
  Update 14 and earlier, and SDK/JRE 1.4.2_16 and earlier
  allows remote attackers to gain privileges via an
  untrusted application, a different issue than
  CVE-2008-1191.
- CVE-2008-1192: Unspecified vulnerability in the Java
  Plug-in for Sun JDK and JRE 6 Update 4 and earlier, and
  5.0 Update 14 and earlier; and SDK and JRE 1.4.2_16 and
  earlier, and 1.3.1_21 and earlier; allows remote
  attackers to bypass the same origin policy and 'execute
  local applications' via unknown vectors.
- CVE-2008-1195: Unspecified vulnerability in Sun JDK and
  Java Runtime Environment (JRE) 6 Update 4 and earlier and
  5.0 Update 14 and earlier; and SDK and JRE 1.4.2_16 and
  earlier; allows remote attackers to access arbitrary
  network services on the local host via unspecified
  vectors related to JavaScript and Java APIs.
- CVE-2008-1196: Stack-based buffer overflow in Java Web
  Start (javaws.exe) in Sun JDK and JRE 6 Update 4 and
  earlier and 5.0 Update 14 and earlier; and SDK and JRE
  1.4.2_16 and earlier; allows remote attackers to execute
  arbitrary code via a crafted JNLP file.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-5131");
script_end_attributes();

script_cve_id("CVE-2008-1158", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1195", "CVE-2008-1196");
script_summary(english: "Check for the java-1_4_2-sun-5131 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.17-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.17-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.17-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.17-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.17-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-demo-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-src-1.4.2.17-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
