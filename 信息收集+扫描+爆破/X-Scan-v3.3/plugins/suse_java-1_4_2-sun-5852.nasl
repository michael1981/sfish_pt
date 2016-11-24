
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41526);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  Security update for Sun Java 1.4.2 (java-1_4_2-sun-5852)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch java-1_4_2-sun-5852");
 script_set_attribute(attribute: "description", value: "The version update to SUN Java 1.4.2sr19 fixes numerous
security issues such as privilege escalations.
(CVE-2008-5360, CVE-2008-5359, CVE-2008-5358,
CVE-2008-5357, CVE-2008-5356, CVE-2008-5344, CVE-2008-5343,
CVE-2008-5342, CVE-2008-5341, CVE-2008-5340, CVE-2008-5339,
CVE-2008-2086, CVE-2008-5355, CVE-2008-5354, CVE-2008-5353,
CVE-2008-5352, CVE-2008-5351, CVE-2008-5350, CVE-2008-5349,
CVE-2008-5348, CVE-2008-5347, CVE-2008-5345, CVE-2008-5346)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch java-1_4_2-sun-5852");
script_end_attributes();

script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5355", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
script_summary(english: "Check for the java-1_4_2-sun-5852 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"java-1_4_2-sun-1.4.2.19-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-alsa-1.4.2.19-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-devel-1.4.2.19-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-jdbc-1.4.2.19-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"java-1_4_2-sun-plugin-1.4.2.19-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
