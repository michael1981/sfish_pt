
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35184);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  squirrelmail: Upgrade to 1.4.10a (squirrelmail-5860)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch squirrelmail-5860");
 script_set_attribute(attribute: "description", value: "This update brings squirrelmail to version 1.4.10a, fixing
a previous regression in cookie handling (novell bug
446400) and a XSS problem (CVE-2008-2379).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch squirrelmail-5860");
script_end_attributes();

script_cve_id("CVE-2008-2379");
script_summary(english: "Check for the squirrelmail-5860 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"squirrelmail-1.4.10a-61.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
