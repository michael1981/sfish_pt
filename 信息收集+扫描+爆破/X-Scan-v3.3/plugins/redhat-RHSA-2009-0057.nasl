
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35429);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0057: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0057");
 script_set_attribute(attribute: "description", value: '
  An updated squirrelmail package that fixes a security issue is now
  available for Red Hat Enterprise Linux 3, 4 and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  SquirrelMail is an easy-to-configure, standards-based, webmail package
  written in PHP. It includes built-in PHP support for the IMAP and SMTP
  protocols, and pure HTML 4.0 page-rendering (with no JavaScript required)
  for maximum browser-compatibility, strong MIME support, address books, and
  folder manipulation.

  The Red Hat SquirrelMail packages provided by the RHSA-2009:0010 advisory
  introduced a session handling flaw. Users who logged back into SquirrelMail
  without restarting their web browsers were assigned fixed session
  identifiers. A remote attacker could make use of that flaw to hijack user
  sessions. (CVE-2009-0030)

  SquirrelMail users should upgrade to this updated package, which contains a
  patch to correct this issue. As well, all users who used affected versions
  of SquirrelMail should review their preferences.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0057.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0030");
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

if ( rpm_check( reference:"squirrelmail-1.4.8-5.el5_2.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-9.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-5.el4_7.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
