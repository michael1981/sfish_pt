
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33580);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0579: vsftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0579");
 script_set_attribute(attribute: "description", value: '
  An updated vsftpd package that fixes a security issue is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure FTP
  server for Linux and Unix-like systems.

  The version of vsftpd as shipped in Red Hat Enterprise Linux 3 when used in
  combination with Pluggable Authentication Modules (PAM) had a memory leak
  on an invalid authentication attempt. Since vsftpd prior to version 2.0.5
  allows any number of invalid attempts on the same connection this memory
  leak could lead to an eventual DoS. (CVE-2008-2375)

  This update mitigates this security issue by including a backported patch
  which terminates a session after a given number of failed log in attempts.
  The default number of attempts is 3 and this can be configured using the
  "max_login_fails" directive.

  All vsftpd users should upgrade to this updated package, which addresses
  this vulnerability.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0579.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2375");
script_summary(english: "Check for the version of the vsftpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vsftpd-1.2.1-3E.16", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
