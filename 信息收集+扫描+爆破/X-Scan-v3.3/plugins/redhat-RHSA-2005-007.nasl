
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16145);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-007: unarj");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-007");
 script_set_attribute(attribute: "description", value: '
  An updated unarj package that fixes a buffer overflow vulnerability and a
  directory traversal vulnerability is now available.

  The unarj program is an archiving utility which can extract ARJ-compatible
  archives.

  A buffer overflow bug was discovered in unarj when handling long file
  names contained in an archive. An attacker could create a specially
  crafted archive which could cause unarj to crash or possibly execute
  arbitrary code when extracted by a victim. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0947 to
  this issue.

  Additionally, a path traversal vulnerability was discovered in unarj. An
  attacker could create a specially crafted archive which would create files
  in the parent ("..") directory when extracted by a victim. When used
  recursively, this vulnerability could be used to overwrite critical system
  files and programs. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1027 to this issue.

  Users of unarj should upgrade to this updated package which contains
  backported patches and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-007.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0947", "CVE-2004-1027");
script_summary(english: "Check for the version of the unarj packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"unarj-2.43-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
