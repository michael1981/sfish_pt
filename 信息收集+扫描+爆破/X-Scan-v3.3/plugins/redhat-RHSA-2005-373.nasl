
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19829);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-373: net");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-373");
 script_set_attribute(attribute: "description", value: '
  Updated net-snmp packages that fix two security issues and various bugs
  are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  SNMP (Simple Network Management Protocol) is a protocol used for network
  management.

  A denial of service bug was found in the way net-snmp uses network stream
  protocols. It is possible for a remote attacker to send a net-snmp agent a
  specially crafted packet which will crash the agent. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-2177 to this issue.

  An insecure temporary file usage bug was found in net-snmp\'s fixproc
  command. It is possible for a local user to modify the content of temporary
  files used by fixproc which can lead to arbitrary command execution. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-1740 to this issue.

  Additionally the following bugs have been fixed:
  - snmpwalk no longer hangs when a non-existant pid is listed.
  - snmpd no longer segfaults due to incorrect handling of lmSensors.
  - an incorrect assignment leading to invalid values in ASN mibs has been
  fixed.
  - on systems running a 64-bit kernel, the values in /proc/net/dev no
  longer become too large to fit in a 32-bit object.
  - the net-snmp-devel packages correctly depend on elfutils-libelf-devel.
  - large file systems are correctly handled
  - snmp daemon now reports gigabit Ethernet speeds correctly
  - fixed consistency between IP adresses and hostnames in configuration file

  All users of net-snmp should upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-373.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1740", "CVE-2005-2177", "CVE-2005-4837");
script_summary(english: "Check for the version of the net packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"net-snmp-5.0.9-2.30E.19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.0.9-2.30E.19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.0.9-2.30E.19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.0.9-2.30E.19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.0.9-2.30E.19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
