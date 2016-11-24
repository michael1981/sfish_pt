
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18147);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-377: sharutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-377");
 script_set_attribute(attribute: "description", value: '
  An updated sharutils package is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The sharutils package contains a set of tools for encoding and decoding
  packages of files in binary or text format.

  A stack based overflow bug was found in the way shar handles the -o option.
  If a user can be tricked into running a specially crafted command, it could
  lead to arbitrary code execution. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-1772 to this issue.
  Please note that this issue does not affect Red Hat Enterprise Linux 4.

  Two buffer overflow bugs were found in sharutils. If an attacker can place
  a malicious \'wc\' command on a victim\'s machine, or trick a victim into
  running a specially crafted command, it could lead to arbitrary code
  execution. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1773 to this issue.

  A bug was found in the way unshar creates temporary files. A local user
  could use symlinks to overwrite arbitrary files the victim running unshar
  has write access to. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0990 to this issue.

  All users of sharutils should upgrade to this updated package, which
  includes backported fixes to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-377.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1772", "CVE-2004-1773", "CVE-2005-0990");
script_summary(english: "Check for the version of the sharutils packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sharutils-4.2.1-8.9.x", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-16.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sharutils-4.2.1-22.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
