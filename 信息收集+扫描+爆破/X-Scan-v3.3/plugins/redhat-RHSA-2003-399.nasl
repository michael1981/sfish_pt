
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12440);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-399: rsync");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-399");
 script_set_attribute(attribute: "description", value: '
  Updated rsync packages are now available that fix a heap overflow in the
  Rsync server.

  rsync is a program for sychronizing files over the network.

  A heap overflow bug exists in rsync versions prior to 2.5.7. On machines
  where the rsync server has been enabled, a remote attacker could use this
  flaw to execute arbitrary code as an unprivileged user. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0962 to this issue.

  All users should upgrade to these erratum packages containing version
  2.5.7 of rsync, which is not vulnerable to this issue.

  NOTE: The rsync server is disabled (off) by default in Red Hat Enterprise
  Linux. To check if the rsync server has been enabled (on), run the
  following command:

  /sbin/chkconfig --list rsync

  If the rsync server has been enabled but is not required, it can be
  disabled by running the following command as root:

  /sbin/chkconfig rsync off

  Red Hat would like to thank the rsync team for their rapid response and
  quick fix for this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-399.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0962");
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

if ( rpm_check( reference:"rsync-2.5.7-0.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
