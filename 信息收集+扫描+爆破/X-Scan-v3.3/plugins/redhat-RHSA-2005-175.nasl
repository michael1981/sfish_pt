
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17265);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-175: kdenetwork");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-175");
 script_set_attribute(attribute: "description", value: '
  Updated kdenetwork packages that fix a file descriptor leak are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  The kdenetwork packages contain a collection of networking applications for
  the K Desktop Environment.

  A bug was found in the way kppp handles privileged file descriptors. A
  malicious local user could make use of this flaw to modify the /etc/hosts
  or /etc/resolv.conf files, which could be used to spoof domain information.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-0205 to this issue.

  Please note that the default installation of kppp on Red Hat Enterprise
  Linux uses consolehelper and is not vulnerable to this issue. However, the
  kppp FAQ provides instructions for removing consolehelper and running kppp
  suid root, which is a vulnerable configuration.

  Users of kdenetwork should upgrade to these updated packages, which contain
  a backported patch, and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-175.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0205");
script_summary(english: "Check for the version of the kdenetwork packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdenetwork-2.2.2-3.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-ppp-2.2.2-3.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-3.1.3-1.8", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.1.3-1.8", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
