
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18240);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-429: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-429");
 script_set_attribute(attribute: "description", value: '
  An updated gaim package that fixes two security issues is now available.

  This update has been rated as having critical security impact by the Red
  Hat
  Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  A stack based buffer overflow bug was found in the way gaim processes a
  message containing a URL. A remote attacker could send a carefully crafted
  message resulting in the execution of arbitrary code on a victim\'s machine.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-1261 to this issue.

  A bug was found in the way gaim handles malformed MSN messages. A remote
  attacker could send a carefully crafted MSN message causing gaim to crash.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-1262 to this issue.

  Users of Gaim are advised to upgrade to this updated package which contains
  backported patches and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-429.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1261", "CVE-2005-1262");
script_summary(english: "Check for the version of the gaim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-1.2.1-6.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-1.2.1-6.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
