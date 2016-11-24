
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27458);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  squirrelmail: fix two cross site scripting bugs (squirrelmail-3944)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch squirrelmail-3944");
 script_set_attribute(attribute: "description", value: "This update of squirrelmail fixes two cross-site-scripting
vulnerabilities that can be used by an attacker to read
opened emails (CVE-2007-1262) and to send email on behalf
of the user (CVE-2007-2589).

This is a reissue of the previous update due to regressions.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch squirrelmail-3944");
script_end_attributes();

script_cve_id("CVE-2007-1262", "CVE-2007-2589");
script_summary(english: "Check for the squirrelmail-3944 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"squirrelmail-1.4.9a-2.6", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
