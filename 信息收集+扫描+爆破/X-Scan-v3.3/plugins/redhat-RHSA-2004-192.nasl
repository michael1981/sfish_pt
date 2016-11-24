
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12497);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-192: rsync");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-192");
 script_set_attribute(attribute: "description", value: '
  An updated rsync package that fixes a directory traversal security flaw is
  now available.

  Rsync is a program for synchronizing files over a network.

  Rsync before 2.6.1 does not properly sanitize paths when running a
  read/write daemon without using chroot. This could allow a remote attacker
  to write files outside of the module\'s "path", depending on the privileges
  assigned to the rsync daemon. Users not running an rsync daemon, running a
  read-only daemon, or running a chrooted daemon are not affected by this
  issue. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-0426 to this issue.

  Users of Rsync are advised to upgrade to this updated package, which
  contains a backported patch and is not affected by this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-192.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0426");
script_summary(english: "Check for the version of the rsync packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rsync-2.5.7-3.21AS", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-4.3E", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
