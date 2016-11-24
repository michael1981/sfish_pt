
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41248);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for IBMJava5 JRE and IBMJava5 SDK (12265)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12265");
 script_set_attribute(attribute: "description", value: 'IBM Java 5 was updated to SR8a to fix a security issue:
CVE-2008-3103: A vulnerability in the Java Management Extensions
(JMX) agent when local monitoring is enabled, allowed remote
attackers to "perform unauthorized operations"
This update also includes new timezone data and fixes missing .systemPrefs
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12265");
script_end_attributes();

script_cve_id("CVE-2008-3103");
script_summary(english: "Check for the security advisory #12265");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"IBMJava5-JRE-1.5.0-0.50", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"IBMJava5-SDK-1.5.0-0.50", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
