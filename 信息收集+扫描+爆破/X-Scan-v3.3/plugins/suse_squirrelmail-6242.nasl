
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(38776);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  SquirrelMail: fixed multiple vulnerabilities (CVE-2009-1578, CVE-2009-1579, CVE-2009-1580 and CVE-2009-1581). (squirrelmail-6242)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch squirrelmail-6242");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities have been fixed in SquirrelMail:
an XSS and input sanitization bug (both CVE-2009-1578),  a
server-side code execution (CVE-2009-1579), a login session
hijacking bug (CVE-2009-1580) and another bug that allowed
phishing and XSS attacks (CVE-2009-1581).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch squirrelmail-6242");
script_end_attributes();

script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
script_summary(english: "Check for the squirrelmail-6242 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"squirrelmail-1.4.18-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
