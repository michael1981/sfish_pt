#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12315);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0655", "CVE-2002-0656");

 script_name(english:"RHSA-2002-157: openssl");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-157");
 
 script_set_attribute(attribute:"description", value:
'
  Updated OpenSSL packages are available which fix several serious buffer
  overflow vulnerabilities.

  OpenSSL is a commercial-grade, full-featured, and Open Source toolkit which
  implements the Secure Sockets Layer (SSL v2/v3) and Transport Layer
  Security (TLS v1) protocols as well as a full-strength general purpose
  cryptography library. A security audit of the OpenSSL code sponsored by
  DARPA found several buffer overflows in OpenSSL which affect versions 0.9.7
  and 0.9.6d and earlier:

  1. The master key supplied by a client to an SSL version 2 server could be
  oversized, causing a stack-based buffer overflow. This issue is remotely
  exploitable. Services that have SSLv2 disabled would not be vulnerable to
  this issue. (CVE-2002-0656)

  2. The SSLv3 session ID supplied to a client from a malicious server could
  be oversized and overrun a buffer. This issue looks to be remotely
  exploitable. (CVE-2002-0656)

  3. Various buffers used for storing ASCII representations of integers were
  too small on 64 bit platforms. This issue may be exploitable.
  (CVE-2002-0655)

  A further issue was found in OpenSSL 0.9.7 that does not affect versions of
  OpenSSL shipped with Red Hat Linux (CVE-2002-0657).

  A large number of applications within Red Hat Linux make use the OpenSSL
  library to provide SSL support. All users are therefore advised to upgrade
  to the errata OpenSSL packages, which contain patches to correct these
  vulnerabilities.

  NOTE:

  Please read the Solution section below as it contains instructions for
  making sure that all SSL-enabled processes are restarted after the update
  is applied.

  Thanks go to the OpenSSL team and Ben Laurie for providing patches for
  these issues.




');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-157.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the openssl packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl-0.9.6b-24", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-24", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.6b-24", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl095a-0.9.5a-14", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-9", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
