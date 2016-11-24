
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17645);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-327: telnet");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-327");
 script_set_attribute(attribute: "description", value: '
  Updated telnet packages that fix two buffer overflow vulnerabilities are
  now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The telnet package provides a command line telnet client. The telnet-server
  package includes a telnet daemon, telnetd, that supports remote login to
  the host machine.

  Two buffer overflow flaws were discovered in the way the telnet client
  handles messages from a server. An attacker may be able to execute
  arbitrary code on a victim\'s machine if the victim can be tricked into
  connecting to a malicious telnet server. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CAN-2005-0468
  and CAN-2005-0469 to these issues.

  Additionally, the following bugs have been fixed in these erratum packages
  for Red Hat Enterprise Linux 2.1 and Red Hat Enterprise Linux 3:

  - telnetd could loop on an error in the child side process

  - There was a race condition in telnetd on a wtmp lock on some occasions

  - The command line in the process table was sometimes too long and caused
  bad output from the ps command

  - The 8-bit binary option was not working

  Users of telnet should upgrade to this updated package, which contains
  backported patches to correct these issues.

  Red Hat would like to thank iDEFENSE for their responsible disclosure of
  this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-327.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0468", "CVE-2005-0469");
script_summary(english: "Check for the version of the telnet packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"telnet-0.17-20.EL2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-20.EL2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-0.17-26.EL3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-26.EL3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-0.17-31.EL4.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-31.EL4.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
