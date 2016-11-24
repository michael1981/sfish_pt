
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33888);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Postfix (postfix-5500)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch postfix-5500");
 script_set_attribute(attribute: "description", value: "A (local) privilege escalation vulnerability as well as a
mailbox ownership problem has been fixed in postfix.
CVE-2008-2936 and CVE-2008-2937 have been assigned to this
problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch postfix-5500");
script_end_attributes();

script_cve_id("CVE-2008-2936", "CVE-2008-2937");
script_summary(english: "Check for the postfix-5500 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"postfix-2.2.9-10.26", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postfix-2.2.9-10.25.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postfix-2.2.9-10.25.3", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
