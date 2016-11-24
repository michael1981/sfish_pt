
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40837);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1287: openssh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1287");
 script_set_attribute(attribute: "description", value: '
  Updated openssh packages that fix a security issue, a bug, and add
  enhancements are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  OpenSSH is OpenBSD\'s SSH (Secure Shell) protocol implementation. These
  packages include the core files necessary for both the OpenSSH client and
  server.

  A flaw was found in the SSH protocol. An attacker able to perform a
  man-in-the-middle attack may be able to obtain a portion of plain text from
  an arbitrary ciphertext block when a CBC mode cipher was used to encrypt
  SSH communication. This update helps mitigate this attack: OpenSSH clients
  and servers now prefer CTR mode ciphers to CBC mode, and the OpenSSH server
  now reads SSH packets up to their full possible length when corruption is
  detected, rather than reporting errors early, reducing the possibility of
  successful plain text recovery. (CVE-2008-5161)

  This update also fixes the following bug:

  * the ssh client hung when trying to close a session in which a background
  process still held tty file descriptors open. With this update, this
  so-called "hang on exit" error no longer occurs and the ssh client closes
  the session immediately. (BZ#454812)

  In addition, this update adds the following enhancements:

  * the SFTP server can now chroot users to various directories, including
  a user\'s home directory, after log in. A new configuration option --
  ChrootDirectory -- has been added to "/etc/ssh/sshd_config" for setting
  this up (the default is not to chroot users). Details regarding configuring
  this new option are in the sshd_config(5) manual page. (BZ#440240)

  * the executables which are part of the OpenSSH FIPS module which is being
  validated will check their integrity and report their FIPS mode status to
  the system log or to the terminal. (BZ#467268, BZ#492363)

  All OpenSSH users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues and add these
  enhancements. After installing this update, the OpenSSH server daemon
  (sshd) will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1287.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5161");
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

if ( rpm_check( reference:"openssh-4.3p2-36.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-4.3p2-36.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-4.3p2-36.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-4.3p2-36.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
