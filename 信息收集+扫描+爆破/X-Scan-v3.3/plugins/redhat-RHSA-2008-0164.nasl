
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31616);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0164: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0164");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages that resolve several issues and fix multiple bugs are
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC.

  A flaw was found in the way the MIT Kerberos Authentication Service and Key
  Distribution Center server (krb5kdc) handled Kerberos v4 protocol packets.
  An unauthenticated remote attacker could use this flaw to crash the
  krb5kdc daemon, disclose portions of its memory, or possibly execute
  arbitrary code using malformed or truncated Kerberos v4 protocol requests.
  (CVE-2008-0062, CVE-2008-0063)

  This issue only affected krb5kdc with Kerberos v4 protocol compatibility
  enabled, which is the default setting on Red Hat Enterprise Linux 4.
  Kerberos v4 protocol support can be disabled by adding "v4_mode=none"
  (without the quotes) to the "[kdcdefaults]" section of
  /var/kerberos/krb5kdc/kdc.conf.

  Jeff Altman of Secure Endpoints discovered a flaw in the RPC library as
  used by MIT Kerberos kadmind server. An unauthenticated remote attacker
  could use this flaw to crash kadmind or possibly execute arbitrary code.
  This issue only affected systems with certain resource limits configured
  and did not affect systems using default resource limits used by Red Hat
  Enterprise Linux 5. (CVE-2008-0947)

  Red Hat would like to thank MIT for reporting these issues.

  Multiple memory management flaws were discovered in the GSSAPI library used
  by MIT Kerberos. These flaws could possibly result in use of already freed
  memory or an attempt to free already freed memory blocks (double-free
  flaw), possibly causing a crash or arbitrary code execution.
  (CVE-2007-5901, CVE-2007-5971)

  In addition to the security issues resolved above, the following bugs were
  also fixed:

  * delegated krb5 credentials were not properly stored when SPNEGO was the
  underlying mechanism during GSSAPI authentication. Consequently,
  applications attempting to copy delegated Kerberos 5 credentials into a
  credential cache received an "Invalid credential was supplied" message
  rather than a copy of the delegated credentials. With this update, SPNEGO
  credentials can be properly searched, allowing applications to copy
  delegated credentials as expected.

  * applications can initiate context acceptance (via gss_accept_sec_context)
  without passing a ret_flags value that would indicate that credentials were
  delegated. A delegated credential handle should have been returned in such
  instances. This updated package adds a temp_ret_flag that stores the
  credential status in the event no other ret_flags value is passed by an
  application calling gss_accept_sec_context.

  * kpasswd did not fallback to TCP on receipt of certain errors, or when a
  packet was too big for UDP. This update corrects this.

  * when the libkrb5 password-routine generated a set-password or
  change-password request, incorrect sequence numbers were generated for all
  requests subsequent to the first request. This caused password change
  requests to fail if the primary server was unavailable. This updated
  package corrects this by saving the sequence number value after the AP-REQ
  data is built and restoring this value before the request is generated.

  * when a user\'s password expired, kinit would not prompt that user to
  change the password, instead simply informing the user their password had
  expired. This update corrects this behavior: kinit now prompts for a new
  password to be set when a password has expired.

  All krb5 users are advised to upgrade to these updated packages, which
  contain backported fixes to address these vulnerabilities and fix these
  bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0164.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
script_summary(english: "Check for the version of the krb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"krb5-devel-1.6.1-17.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.6.1-17.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.6.1-17.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.6.1-17.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
