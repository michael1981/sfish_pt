
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33897);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  postfix: local privilege escalation (CVE-2008-2936 and CVE-2008-2937) (postfix-5501)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch postfix-5501");
 script_set_attribute(attribute: "description", value: "A (local) privilege escalation vulnerability as well as a
mailbox ownership problem has been fixed in postfix.
CVE-2008-2936 and CVE-2008-2937 have been assigned to this
problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch postfix-5501");
script_end_attributes();

script_cve_id("CVE-2008-2936", "CVE-2008-2937");
script_summary(english: "Check for the postfix-5501 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"postfix-2.4.5-20.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postfix-devel-2.4.5-20.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postfix-mysql-2.4.5-20.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postfix-postgresql-2.4.5-20.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
