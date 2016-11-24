
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12309);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-131: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-131");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages are now available for Red Hat Linux Advanced
  Server. These updates fix an input validation error in OpenSSH.

  OpenSSH provides an implementation of the SSH (secure shell) protocol used
  for logging into and executing commands on remote machines.

  Versions of the OpenSSH server between 2.3.1 and 3.3 contain an input
  validation error that can result in an integer overflow and privilege
  escalation.

  At this time, Red Hat does not believe that the default installation of
  OpenSSH on Red Hat Linux is vulnerable to this issue; however a user would
  be vulnerable if the configuration option "PAMAuthenticationViaKbdInt" is
  enabled in the sshd configuration file (it is not enabled by default).

  We have applied the security fix provided by the OpenSSH team to these
  errata packages which are based on OpenSSH 3.1p1. This should minimize the
  impact of upgrading to our errata packages.

  All users of OpenSSH should update to these errata packages which are not
  vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-131.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0640");
script_summary(english: "Check for the version of the openssh packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openssh-3.1p1-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.1p1-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.1p1-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.1p1-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.1p1-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
