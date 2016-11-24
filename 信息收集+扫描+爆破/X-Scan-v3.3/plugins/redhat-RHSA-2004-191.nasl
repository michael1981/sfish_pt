
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12496);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-191: cadaver");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-191");
 script_set_attribute(attribute: "description", value: '
  An updated cadaver package is now available that fixes a vulnerability in
  neon which could be exploitable by a malicious DAV server.

  cadaver is a command-line WebDAV client that uses inbuilt code from neon,
  an HTTP and WebDAV client library.

  Stefan Esser discovered a flaw in the neon library which allows a heap
  buffer overflow in a date parsing routine. An attacker could create
  a malicious WebDAV server in such a way as to allow arbitrary code
  execution on the client should a user connect to it using cadaver. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0398 to this issue.

  Users of cadaver are advised to upgrade to this updated package, which
  contains a patch correcting this issue.

  This issue does not affect Red Hat Enterprise Linux 3.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-191.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0398");
script_summary(english: "Check for the version of the cadaver packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cadaver-0.22.1-1.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
