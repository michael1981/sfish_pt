
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25270);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2007-0358: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0358");
 script_set_attribute(attribute: "description", value: '
  A new squirrelmail package that fixes security issues is now available for
  Red Hat Enterprise Linux 3, 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP4.

  Several HTML filtering bugs were discovered in SquirrelMail. An attacker
  could inject arbitrary JavaScript leading to cross-site scripting attacks
  by sending an e-mail viewed by a user within SquirrelMail.
  (CVE-2007-1262)

  Squirrelmail did not sufficiently check arguments to IMG tags in HTML
  e-mail messages. This could be exploited by an attacker by sending
  arbitrary e-mail messages on behalf of a squirrelmail user tricked into
  opening
  a maliciously crafted HTML e-mail message. (CVE-2007-2589)

  Users of SquirrelMail should upgrade to this erratum package, which
  contains a backported patch to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0358.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1262", "CVE-2007-2589");
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

if ( rpm_check( reference:"squirrelmail-1.4.8-4.0.1.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-6.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-4.0.1.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
