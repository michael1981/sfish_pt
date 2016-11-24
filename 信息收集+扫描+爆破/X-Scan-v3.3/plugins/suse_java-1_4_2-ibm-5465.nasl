
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34024);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for IBM Java 1.4.2 (java-1_4_2-ibm-5465)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-ibm-5465");
 script_set_attribute(attribute: "description", value: "This update of IBM Java to 1.4.2 SR11 fixes various
security problems:
* CVE-2008-1196: Stack-based buffer overflow in Java Web
  Start (javaws.exe) allows remote attackers to execute
  arbitrary code via a crafted JNLP file.
* CVE-2008-1187: Unspecified vulnerability in the Java
  Runtime Environment (JRE) allows remote attackers to
  cause a denial of service (JRE crash) and possibly
  execute arbitrary code via unknown vectors related to
  XSLT transforms.
* CVE-2007-5240: Visual truncation vulnerability in the
  Java Runtime Environment allows remote attackers to
  circumvent display of the untrusted-code warning banner
  by creating a window larger than the workstation screen.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-ibm-5465");
script_end_attributes();

script_cve_id("CVE-2007-5240", "CVE-2008-1187", "CVE-2008-1196");
script_summary(english: "Check for the java-1_4_2-ibm-5465 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_4_2-ibm-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-devel-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-jdbc-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-plugin-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-devel-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-jdbc-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-ibm-plugin-1.4.2_sr11-0.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
