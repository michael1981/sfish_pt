
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7626
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34138);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-7626: drupal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7626 (drupal)");
 script_set_attribute(attribute: "description", value: "Equipped with a powerful blend of features, Drupal is a Content Management
System written in PHP that can support a variety of websites ranging from
personal weblogs to large community-driven websites.  Drupal is highly
configurable, skinnable, and secure.

-
Update Information:

Update to 6.4, security fixes:    SA-2008-047 ([9]http://drupal.org/node/295053
)  -
multiple XSS issues (CVE-2008-3740, CVE-2008-3741)  - unrestricted upload
vulnerability (CVE-2008-3742)  - multiple CSRF issues (CVE-2008-3743,
CVE-2008-3744)  - upload module privilege escalation (CVE-2008-3745)    Remembe
r
to log in to your site as the admin user before upgrading this package. After
upgrading the package, browse to [10]http://host/drupal/update.php to run the
upgrade script.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3741", "CVE-2008-3743", "CVE-2008-3745");
script_summary(english: "Check for the version of the drupal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-6.4-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
