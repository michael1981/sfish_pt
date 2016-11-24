
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25142);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0252: sendmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0252");
 script_set_attribute(attribute: "description", value: '
  Updated sendmail packages that fix a security issue and various bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Sendmail is a very widely used Mail Transport Agent (MTA). MTAs deliver
  mail from one machine to another. Sendmail is not a client program, but
  rather a behind-the-scenes daemon that moves email over networks or the
  Internet to its final destination.

  The configuration of Sendmail on Red Hat Enterprise Linux was found to not
  reject the "localhost.localdomain" domain name for e-mail messages that
  came from external hosts. This could have allowed remote attackers to
  disguise spoofed messages (CVE-2006-7176).

  This updated package also fixes the following bugs:

  * Infinite loop within tls read.

  * Incorrect path to selinuxenabled in initscript.

  * Build artifacts from sendmail-cf package.

  * Missing socketmap support.

  * Add support for CipherList configuration directive.

  * Path for aliases file.

  * Failure of shutting down sm-client.

  * Allows to specify persistent queue runners.

  * Missing dnl for SMART_HOST define.

  * Fixes connections stay in CLOSE_WAIT.

  All users of Sendmail should upgrade to these updated packages, which
  contains backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0252.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-7176");
script_summary(english: "Check for the version of the sendmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sendmail-8.13.1-3.2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.13.1-3.2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.13.1-3.2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.13.1-3.2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
