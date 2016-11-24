
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19902);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:146: php-pear");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:146 (php-pear).");
 script_set_attribute(attribute: "description", value: "A problem was discovered in the PEAR XML-RPC Server package included
in the php-pear package. If a PHP script which implements the XML-RPC
Server is used, it would be possible for a remote attacker to construct
an XML-RPC request which would cause PHP to execute arbitrary commands
as the 'apache' user.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:146");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2498");
script_summary(english: "Check for the version of the php-pear package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"php-pear-4.3.4-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.8-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.10-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-pear-", release:"MDK10.0")
 || rpm_exists(rpm:"php-pear-", release:"MDK10.1")
 || rpm_exists(rpm:"php-pear-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2498", value:TRUE);
}
exit(0, "Host is not affected");
