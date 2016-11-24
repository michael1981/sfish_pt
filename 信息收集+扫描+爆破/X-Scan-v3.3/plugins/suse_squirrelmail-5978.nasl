
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35598);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  squirrelmail: fix for static cookies (squirrelmail-5978)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch squirrelmail-5978");
 script_set_attribute(attribute: "description", value: "This update of squirrelmail corrects a problem introduced
by a patch for CVE-2008-3663 that caused cookies to be
static. (CVE-2009-0030)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch squirrelmail-5978");
script_end_attributes();

script_cve_id("CVE-2008-3663", "CVE-2009-0030");
script_summary(english: "Check for the squirrelmail-5978 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"squirrelmail-1.4.17-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
