
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12459);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-045: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-045");
 script_set_attribute(attribute: "description", value: '
  Updated Gaim packages that fix a pair of security vulnerabilities are now
  available.

  Gaim is an instant messenger client that can handle multiple protocols.

  Stefan Esser audited the Gaim source code and found a number of bugs that
  have security implications. Many of these bugs do not affect the version
  of Gaim distributed with version 2.1 of Red Hat Enterprise Linux.

  A buffer overflow exists in the HTTP Proxy connect code. If Gaim is
  configured to use an HTTP proxy for connecting to a server, a malicious
  HTTP proxy could run arbitrary code as the user running Gaim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0006 to this issue.

  An integer overflow in Gaim 0.74 and earlier, when allocating memory for a
  directIM packet for AIM/Oscar, results in heap overflow. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0008 to this issue.

  Users of Gaim should upgrade to these erratum packages, which contain
  a backported security patch correcting this issue.

  Red Hat would like to thank Steffan Esser for finding and reporting these
  issues and Jacques A. Vidrine for providing initial patches.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-045.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0006", "CVE-2004-0008");
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

if ( rpm_check( reference:"gaim-0.59.1-0.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
