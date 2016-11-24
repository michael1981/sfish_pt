
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12461);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-050: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-050");
 script_set_attribute(attribute: "description", value: '
  New mutt packages that fix a remotely-triggerable crash in the menu drawing
  code are now available.

  Mutt is a text-mode mail user agent.

  A bug was found in the index menu code in versions of mutt. A remote
  attacker could send a carefully crafted mail message that can cause mutt
  to segfault and possibly execute arbitrary code as the victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0078 to this issue.

  It is recommended that all mutt users upgrade to these updated packages,
  which contain a backported security patch and are not vulnerable to this
  issue.

  Red Hat would like to thank Niels Heinen for reporting this issue.

  Note: mutt-1.2.5.1 in Red Hat Enterprise Linux 2.1 is not vulnerable to
  this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-050.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0078");
script_summary(english: "Check for the version of the mutt packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mutt-1.4.1-3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
