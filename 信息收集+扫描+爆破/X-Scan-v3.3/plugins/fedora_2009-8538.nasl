
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8538
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40601);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-8538: wordpress-mu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8538 (wordpress-mu)");
 script_set_attribute(attribute: "description", value: "WordPress-MU is a derivative of the WordPress blogging codebase, to allow
one instance to serve multiple users.

-
Update Information:

Update spans MU-versions for the following security releases from upstream:
[9]http://wordpress.org/development/2009/08/2-8-4-security-release/
[10]http://wordpress.org/development/2009/08/wordpress-2-8-3-security-release/

Update information :

* Backport of XSS fixes from WordPress 2.8.2    * Backport of security fixes fo
r
admin.php?page= bugs (CVE-2009-2334) Backport of security fixes for
admin.php?page= bugs (CVE-2009-2334) Backport of security fixes for
admin.php?page= bugs (CVE-2009-2334)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1030", "CVE-2009-2334", "CVE-2009-2336");
script_summary(english: "Check for the version of the wordpress-mu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"wordpress-mu-2.8.4a-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
