
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32116);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for nagios (nagios-5165)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch nagios-5165");
 script_set_attribute(attribute: "description", value: "This update fixes several cross site scripting (XSS) issues
in nagios (CVE-2007-5624, CVE-2007-5803, CVE-2008-1360).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch nagios-5165");
script_end_attributes();

script_cve_id("CVE-2007-5624", "CVE-2007-5803", "CVE-2008-1360");
script_summary(english: "Check for the nagios-5165 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"nagios-2.6-13.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"nagios-www-2.6-13.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
