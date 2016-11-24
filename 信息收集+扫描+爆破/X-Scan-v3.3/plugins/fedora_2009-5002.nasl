
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5002
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38798);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-5002: drupal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5002 (drupal)");
 script_set_attribute(attribute: "description", value: "Equipped with a powerful blend of features, Drupal is a Content Management
System written in PHP that can support a variety of websites ranging from
personal weblogs to large community-driven websites.  Drupal is highly
configurable, skinnable, and secure.

-
Update Information:

Fixes SA-CORE-2009-006 ( [9]http://drupal.org/node/461886 ).    Remember to log
in
to your site as the admin user before upgrading this package. After upgrading
the package, browse to [10]http://host/drupal/update.php to run the upgrade scr
ipt.
When outputting user-supplied data Drupal strips potentially dangerous HTML
attributes and tags or escapes characters which have a special meaning in HTML.
This output filtering secures the site against cross site scripting attacks via
user input.    Certain byte sequences that are valid in the UTF-8 specification
are potentially dangerous when interpreted as UTF-7. Internet Explorer 6 and 7
may decode these characters as UTF-7 if they appear before the <meta http-equiv
='Content-Type' /> tag that specifies the page content as UTF-8, despite the
fact that Drupal also sends a real HTTP header specifying the content as UTF-8.
This enables attackers to execute cross site scripting attacks with UTF-7. SA-
CORE-2009-005 - Drupal core - Cross site scripting contained an incomplete fix
for the issue. HTML exports of books are still vulnerable, which means that
anyone with edit permissions for pages in outlines is able to insert arbitrary
HTML and script code in these exports.    Additionally, the taxonomy module
allows users with the 'administer taxonomy' permission to inject arbitrary HTML
and script code in the help text of any vocabulary.    Wikipedia has more
information about cross site scripting (XSS).
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the drupal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-6.12-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
