
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28243);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1003: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1003");
 script_set_attribute(attribute: "description", value: '
  Updated OpenSSL packages that correct a security issue and various bugs are
  now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, and is also a
  full-strength general-purpose cryptography library.

  A flaw was found in the SSL_get_shared_ciphers() utility function. An
  attacker could send a list of ciphers to an application that used this
  function and overrun a buffer by a single byte (CVE-2007-5135). Few
  applications make use of this vulnerable function and generally it is used
  only when applications are compiled for debugging.

  A number of possible side-channel attacks were discovered affecting
  OpenSSL. A local attacker could possibly obtain RSA private keys being used
  on a system. In practice these attacks would be difficult to perform
  outside of a lab environment. This update contains backported patches to
  mitigate these issues. (CVE-2007-3108)

  As well, these updated packages fix the following bugs:

  * multithreaded applications could cause a segmentation fault or deadlock
  when calling the random number generator initialization (RAND_poll) in the
  OpenSSL library, for a large number of threads simultaneously.

  * in certain circumstances, if an application using the OpenSSL library
  reused the SSL session cache for multiple purposes (with various parameters
  of the SSL protocol), the session parameters could be mismatched.

  * a segmentation fault could occur when a corrupted pkcs12 file was being
  loaded using the "openssl pkcs12 -in [pkcs12-file]" command, where
  [pkcs12-file] is the pkcs12 file.

  Users of OpenSSL should upgrade to these updated packages, which contain
  backported patches to resolve these issues.

  Note: After installing this update, users are advised to either restart all
  services that use OpenSSL or restart their system.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1003.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3108", "CVE-2007-5135");
script_summary(english: "Check for the version of the openssl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openssl-0.9.7a-43.17.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-43.17.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-43.17.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
