
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42034);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  squirrelmail security update (squirrelmail-6457)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch squirrelmail-6457");
 script_set_attribute(attribute: "description", value: "The previous fix for a vulnerability that allowed an
attacker to run arbitrary commands on the server was
incomplete (CVE-2009-1381).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch squirrelmail-6457");
script_end_attributes();

script_cve_id("CVE-2009-1381");
script_summary(english: "Check for the squirrelmail-6457 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"squirrelmail-1.4.20-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
