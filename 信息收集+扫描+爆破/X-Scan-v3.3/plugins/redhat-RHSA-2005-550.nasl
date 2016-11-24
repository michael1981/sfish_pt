
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19830);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-550: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-550");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages that fix a potential security vulnerability and
  various other bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure SHell) protocol implementation. This
  includes the core files necessary for both the OpenSSH client and server.

  A bug was found in the way the OpenSSH server handled the MaxStartups and
  LoginGraceTime configuration variables. A malicious user could connect to
  the SSH daemon in such a way that it would prevent additional logins from
  occuring until the malicious connections are closed. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-2069 to this issue.

  Additionally, the following issues are resolved with this update:

  - The -q option of the ssh client did not suppress the banner message sent
  by the server, which caused errors when used in scripts.

  - The sshd daemon failed to close the client connection if multiple X
  clients were forwarded over the connection and the client session exited.

  - The sftp client leaked memory if used for extended periods.

  - The sshd daemon called the PAM functions incorrectly if the user was
  unknown on the system.

  All users of openssh should upgrade to these updated packages, which
  contain backported patches and resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-550.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-2069");
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

if ( rpm_check( reference:"openssh-3.6.1p2-33.30.6", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.6.1p2-33.30.6", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.6.1p2-33.30.6", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.6.1p2-33.30.6", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.6.1p2-33.30.6", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
