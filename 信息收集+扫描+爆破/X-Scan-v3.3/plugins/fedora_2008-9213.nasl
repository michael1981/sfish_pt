
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9213
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34672);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-9213: drupal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9213 (drupal)");
 script_set_attribute(attribute: "description", value: "Equipped with a powerful blend of features, Drupal is a Content Management
System written in PHP that can support a variety of websites ranging from
personal weblogs to large community-driven websites.  Drupal is highly
configurable, skinnable, and secure.

-
Update Information:

Update to 6.6, security fixes:    SA-2008-067 ( [9]http://drupal.org/node/32482
4 )
------------DESCRIPTION------------    Multiple vulnerabilities and weaknesses
were discovered in Drupal.    ------------FILE INCLUSION------------    On a
server configured for IP-based virtual hosts, Drupal may be caused to  include
and execute specifically named files outside of its root directory.     This bu
g
affects both Drupal 5 and Drupal 6.    ------------CROSS SITE
SCRIPTING------------    The title of book pages is not always properly escaped
,
enabling users with the  'create book content' permission or the permission to
edit any node in the book  hierarchy to insert arbitrary HTML and script code
into pages. Such a Cross site  scripting [ [10]http://en.wikipedia.org/wiki/Cro
ss-
site_scripting ] attack may lead  to the attacker gaining administrator access.
This bug affects Drupal 6.      Remember to log in to your site as the admin
user before upgrading this package. After upgrading the package, browse to
[11]http://host/drupal/update.php to run the upgrade script.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3661");
script_summary(english: "Check for the version of the drupal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-6.6-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
