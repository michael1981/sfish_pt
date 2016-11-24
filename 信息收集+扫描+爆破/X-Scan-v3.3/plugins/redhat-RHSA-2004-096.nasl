
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12475);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-096: wu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-096");
 script_set_attribute(attribute: "description", value: '
  An updated wu-ftpd package that fixes two security issues is now available.

  The wu-ftpd package contains the Washington University FTP (File Transfer
  Protocol) server daemon. FTP is a method of transferring files between
  machines.

  Glenn Stewart discovered a flaw in wu-ftpd. When configured with
  "restricted-gid home", an authorized user could use this flaw to
  circumvent the configured home directory restriction by using chmod. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0148 to this issue.

  Michael Hendrickx found a flaw in the S/Key login handling. On servers
  using S/Key authentication, a remote attacker could overflow a buffer and
  potentially execute arbitrary code.

  Users of wu-ftpd are advised to upgrade to this updated package, which
  contains backported security patches and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-096.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-1329", "CVE-2004-0148", "CVE-2004-0185");
script_summary(english: "Check for the version of the wu packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wu-ftpd-2.6.1-22", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
