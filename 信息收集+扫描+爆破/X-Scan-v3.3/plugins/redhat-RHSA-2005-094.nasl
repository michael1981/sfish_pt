
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17184);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-094: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-094");
 script_set_attribute(attribute: "description", value: '
  An updated Thunderbird package that fixes a security issue is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  Thunderbird is a standalone mail and newsgroup client.

  A bug was found in the way Thunderbird handled cookies when loading content
  over HTTP regardless of the user\'s preference. It is possible that a
  particular user could be tracked through the use of malicious mail messages
  which load content over HTTP. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-0149 to this issue.

  Users of Thunderbird are advised to upgrade to this updated package,
  which contains Thunderbird version 1.0 and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-094.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0146", "CVE-2005-0149");
script_summary(english: "Check for the version of the thunderbird packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"thunderbird-1.0-1.1.EL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
