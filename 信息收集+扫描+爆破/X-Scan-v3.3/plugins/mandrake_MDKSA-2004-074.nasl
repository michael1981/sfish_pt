
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14172);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2004:074: webmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:074 (webmin).");
 script_set_attribute(attribute: "description", value: "Unknown vulnerability in Webmin 1.140 allows remote attackers to
bypass access control rules and gain read access to configuration
information for a module. (CVE-2004-0582)
The account lockout functionality in Webmin 1.140 does not parse
certain character strings, which allows remote attackers to conduct a
brute force attack to guess user IDs and passwords. (CVE-2004-0583)
The updated packages are patched to correct the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:074");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0582", "CVE-2004-0583");
script_summary(english: "Check for the version of the webmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"webmin-1.121-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"webmin-1.070-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"webmin-1.100-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK10.0")
 || rpm_exists(rpm:"webmin-", release:"MDK9.1")
 || rpm_exists(rpm:"webmin-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0582", value:TRUE);
 set_kb_item(name:"CVE-2004-0583", value:TRUE);
}
exit(0, "Host is not affected");
