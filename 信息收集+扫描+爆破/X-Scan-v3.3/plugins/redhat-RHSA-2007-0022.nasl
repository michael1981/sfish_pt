
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24317);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0022: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0022");
 script_set_attribute(attribute: "description", value: '
  A new squirrelmail package that fixes security issues is now available for
  Red Hat Enterprise Linux 3 and 4.

  SquirrelMail is a standards-based webmail package written in PHP.

  Several cross-site scripting bugs were discovered in SquirrelMail. An
  attacker could inject arbitrary Javascript or HTML content into
  SquirrelMail pages by tricking a user into visiting a carefully crafted
  URL. (CVE-2006-6142)

  Users of SquirrelMail should upgrade to this erratum package, which
  contains a backported patch to correct these issues.

  Notes:
  - After installing this update, users are advised to restart their
  httpd service to ensure that the updated version functions correctly.
  - config.php should NOT be modified, please modify config_local.php
  instead.
  - Known Bug: The configuration generator may potentially produce bad
  options that interfere with the operation of this application. Applying
  specific config changes to config_local.php manually is recommended.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0022.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6142");
script_summary(english: "Check for the version of the squirrelmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squirrelmail-1.4.8-4.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-4.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
