
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36081);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  phpMyAdmin: multiple vulnerabilities (phpMyAdmin-6133)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch phpMyAdmin-6133");
 script_set_attribute(attribute: "description", value: "This update of phpMyAdmin fixes multiple vulnerabilities:
- CVE-2009-1148: directory traversal
- CVE-2009-1149: CRLF injection
- CVE-2009-1150: cross-site scripting
- CVE-2009-1151: static code injection
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch phpMyAdmin-6133");
script_end_attributes();

script_cve_id("CVE-2009-1148", "CVE-2009-1149", "CVE-2009-1150", "CVE-2009-1151");
script_summary(english: "Check for the phpMyAdmin-6133 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"phpMyAdmin-2.11.9.5-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
