
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25334);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0348: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0348");
 script_set_attribute(attribute: "description", value: '
  Updated PHP packages that fix several security issues are now available for
  Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A heap buffer overflow flaw was found in the PHP \'xmlrpc\' extension. A
  PHP script which implements an XML-RPC server using this extension
  could allow a remote attacker to execute arbitrary code as the \'apache\'
  user. Note that this flaw does not affect PHP applications using the
  pure-PHP XML_RPC class provided in /usr/share/pear. (CVE-2007-1864)

  A flaw was found in the PHP \'ftp\' extension. If a PHP script used this
  extension to provide access to a private FTP server, and passed untrusted
  script input directly to any function provided by this extension, a remote
  attacker would be able to send arbitrary FTP commands to the server.
  (CVE-2007-2509)

  A buffer overflow flaw was found in the PHP \'soap\' extension, regarding the
  handling of an HTTP redirect response when using the SOAP client provided
  by this extension with an untrusted SOAP server. No mechanism to trigger
  this flaw remotely is known. (CVE-2007-2510)

  Users of PHP should upgrade to these updated packages which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0348.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1864", "CVE-2007-2509", "CVE-2007-2510");
script_summary(english: "Check for the version of the php packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"php-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-bcmath-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-common-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-dba-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pdo-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-snmp-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xml-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-5.1.6-12.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
