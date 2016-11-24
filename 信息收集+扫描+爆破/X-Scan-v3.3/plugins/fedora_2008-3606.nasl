
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3606
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33231);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-3606: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3606 (php)");
 script_set_attribute(attribute: "description", value: "PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated webpages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts.

The php package contains the module which adds support for the PHP
language to Apache HTTP Server.

-
Update Information:

This release updates PHP to the latest upstream version 5.2.6, fixing multiple
bugs and security issues.    See upstream release notes for further details:
[9]http://www.php.net/releases/5_2_6.php    It was discovered that the PHP
escapeshellcmd() function did not properly escape multi-byte characters which
are not valid in the locale used by the script. This could allow an attacker to
bypass quoting restrictions imposed by escapeshellcmd() and execute arbitrary
commands if the PHP script was using certain locales. Scripts using the default
UTF-8 locale are not affected by this issue. (CVE-2008-2051)    It was
discovered that a PHP script using the transparent session ID configuration
option, or using the output_add_rewrite_var() function, could leak session
identifiers to external web sites. If a page included an HTML form which is
posted to a third-party web site, the user's session ID would be included in th
e
form data and passed to that web site. (CVE-2007-5899)    It was discovered tha
t
PHP did not properly seed its pseudo-random number generator used by functions
such as rand() and mt_rand(), possibly allowing an attacker to easily predict
the generated pseudo-random values. (CVE-2008-2107, CVE-2008-2108)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5899", "CVE-2008-0599", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");
script_summary(english: "Check for the version of the php package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-5.2.6-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
