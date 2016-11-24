
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11576
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35234);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-11576: phpPgAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11576 (phpPgAdmin)");
 script_set_attribute(attribute: "description", value: "phpPgAdmin is a fully functional web-based administration utility for
a PostgreSQL database server. It handles all the basic functionality
as well as some advanced features such as triggers, views and
functions (stored procedures). It also has Slony-I support.

-
Update Information:

This release fixes some bugs, and also fixes a security issue:     * Fix bug
where long SQL queries get truncated  * Fix createFunction method on PostgreSQL
< 7.3   * Fix bug with alter schema in PostgreSQL < 7.4   * Remove alter domain
for PostgreSQL < 7.4   * Fix local file inclusion vulnerability: (CVE-2008-5587
)
[9]http://www.securityfocus.com/bid/32670/      Unset language variable before
determine file includes
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5587");
script_summary(english: "Check for the version of the phpPgAdmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"phpPgAdmin-4.2.2-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
