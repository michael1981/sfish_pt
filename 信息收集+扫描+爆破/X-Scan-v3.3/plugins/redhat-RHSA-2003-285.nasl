
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12423);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-285: sane");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-285");
 script_set_attribute(attribute: "description", value: '
  Updated SANE packages that resolve a number of vulnerabilities with the
  saned daemon are now available.

  SANE is a package for using document scanners.

  Sane includes a daemon program (called saned) that enables a single machine
  connected to a scanner to be used remotely. This program contains several
  vulnerabilities.

  NOTE: Although the SANE packages include this program, it is not used by
  default under Red Hat Enterprise Linux.

  The IP address of the remote host is only checked after the first
  communication occurs, causing saned.conf restrictions to be ineffective for
  the first communication. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0773 to this issue.

  A connection that is dropped early causes one of several problems. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CAN-2003-0774, CAN-2003-0775, and CAN-2003-0777 to these issues.

  Lack of error checking can cause various other unfavorable consequences.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CAN-2003-0776 and CAN-2003-0778 to these issues.

  Users of SANE (particularly those that use saned for remote scanner access)
  should upgrade to these errata packages, which contain a backported
  security patch to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-285.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
script_summary(english: "Check for the version of the sane packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sane-backends-1.0.5-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sane-backends-devel-1.0.5-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
