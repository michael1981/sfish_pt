
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18276);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:087: tcpdump");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:087 (tcpdump).");
 script_set_attribute(attribute: "description", value: "A number of Denial of Service vulnerabilities were discovered in the
way that tcpdump processes certain network packets. If abused, these
flaws can allow a remote attacker to inject a carefully crafted packet
onto the network, crashing tcpdump.
The provided packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:087");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1278", "CVE-2005-1279", "CVE-2005-1280");
script_summary(english: "Check for the version of the tcpdump package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tcpdump-3.8.1-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.8.3-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.8.3-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK10.0")
 || rpm_exists(rpm:"tcpdump-", release:"MDK10.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1278", value:TRUE);
 set_kb_item(name:"CVE-2005-1279", value:TRUE);
 set_kb_item(name:"CVE-2005-1280", value:TRUE);
}
exit(0, "Host is not affected");
