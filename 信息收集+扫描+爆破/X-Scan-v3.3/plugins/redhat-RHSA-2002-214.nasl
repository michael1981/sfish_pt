#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12326);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0985", "CVE-2002-0986");

 script_name(english:"RHSA-2002-214: php");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-214");
 
 script_set_attribute(attribute:"description", value:
'
  PHP versions up to and including 4.2.2 contain vulnerabilities in the mail
  ()
  function, allowing local script authors to bypass safe mode restrictions
  and possibly allowing remote attackers to insert arbitrary mail headers or
  content.

  [Updated 13 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP server.

  The mail function in PHP 4.x to 4.2.2 may allow local script authors to
  bypass safe mode restrictions and modify command line arguments to the
  MTA (such as sendmail) in the 5th argument to mail(), altering MTA
  behavior and possibly executing arbitrary local commands.

  The mail function in PHP 4.x to 4.2.2 does not filter ASCII control
  characters from its arguments, which could allow remote attackers to
  modify mail message content, including mail headers, and possibly use
  PHP as a "spam proxy."

  Script authors should note that all input data should be checked for
  unsafe data by any PHP scripts which call functions such as mail().

  Note that this PHP errata, as did RHSA-2002:129, enforces memory limits on
  the size of the PHP process to prevent a badly generated script from
  becoming a possible source for a denial of service attack. The default
  process size is 8Mb, though you can adjust this as you deem necessary
  through the php.ini directive memory_limit. For example, to change the
  process memory limit to 4MB, add the following:

  memory_limit 4194304

  Important Note:
  There are special instructions you should follow regarding your
  /etc/php.ini configuration file in the "Solution" section below.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-214.html");
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
if ( rpm_check( reference:"php-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.1.6", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
