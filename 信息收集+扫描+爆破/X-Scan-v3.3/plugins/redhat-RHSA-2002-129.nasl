#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12307);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2001-1246");

 script_name(english:"RHSA-2002-129: php");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-129");
 
 script_set_attribute(attribute:"description", value:
'
  PHP versions earlier than 4.1.0 contain a vulnerability that could allow
  arbitrary commands to be executed.

  [updated 22 Aug 2002]
  The initial set of errata packages contained an incorrect set of
  dependencies. This meant that a number of packages would need to be
  installed before php that were not essential to the operation of php.
  Updated errata packages are included with this advisory that have corrected
  dependencies.

  PHP is an HTML-embedded scripting language commonly used with Apache. PHP
  versions 4.0.5 through 4.1.0 in safe mode do not properly cleanse the 5th
  parameter to the mail() function. This vulnerability allows local users and
  possibly remote attackers to execute arbitrary commands via shell
  metacharacters.

  Red Hat Linux Advanced Server version 2.1 shipped with PHP 4.0.6.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2001-1246 to this issue.

  All users of PHP should upgrade to these errata packages containing PHP
  4.1.2, which is not vulnerable to this issue.

  Note:

  This PHP errata enforces memory limits on the size of the PHP process to
  prevent a badly generated script from becoming a possible source for a
  denial of service attack. The default process size is 8Mb though you can
  adjust this as you deem necessary thought the php.ini directive
  memory_limit. For example, to change the process memory limit to 4MB, add
  the following:

  memory_limit 4194304

  Important Installation Note:

  There are special instructions you should follow regarding your
  /etc/php.ini configuration file in the "Solution" section below.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-129.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the php packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"php-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.1.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
