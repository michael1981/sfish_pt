
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41315);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for IBM Java5 JRE and SDK (12461)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12461");
 script_set_attribute(attribute: "description", value: 'The IBM JRE/JDK version 5 was updated to Service Release 10.
It fixes a number of bugs and likely also several security issues.
As usual IBM does not publish fixed security issues on the release date  so a
detailed list cannot be given at this time.
Please check 
http://www.ibm.com/developerworks/java/jdk/alerts/ for updated
information.
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 12461");
script_end_attributes();

script_summary(english: "Check for the security advisory #12461");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"IBMJava5-JRE-1.5.0-0.70", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"IBMJava5-SDK-1.5.0-0.70", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
