
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12407);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-224: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-224");
 script_set_attribute(attribute: "description", value: '
  Updated OpenSSH packages are now available. These updates close an
  information leak caused by sshd\'s interaction with the PAM system.

  OpenSSH is a suite of network connectivity tools that can be used to
  establish encrypted connections between systems on a network and can
  provide interactive login sessions and port forwarding, among other
  functions.

  When configured to allow password-based or challenge-response
  authentication, sshd (the OpenSSH server) uses PAM (Pluggable
  Authentication Modules) to verify the user\'s password. Under certain
  conditions, OpenSSH versions prior to 3.6.1p1 reject an invalid
  authentication attempt without first attempting authentication using PAM.

  If PAM is configured with its default failure delay, the amount of time
  sshd takes to reject an invalid authentication request varies widely enough
  that the timing variations could be used to deduce whether or not an
  account with a specified name existed on the server. This information
  could then be used to narrow the focus of an attack against some other
  system component.

  These updates contain backported fixes that cause sshd to always attempt
  PAM authentication when performing password and challenge-response
  authentication for clients.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-224.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0190");
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

if ( rpm_check( reference:"openssh-3.1p1-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.1p1-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.1p1-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.1p1-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.1p1-8", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
