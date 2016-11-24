
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14129);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:030: tcpdump");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:030 (tcpdump).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in tcpdump versions prior
to 3.8.1 that, if fed a maliciously crafted packet, could be exploited
to crash tcpdump. These vulnerabilities include:
Remote attackers can cause a denial of service (crash) via ISAKMP packets
containing a Delete payload with a large number of SPI's, which causes
an out-of-bounds read. (CVE-2004-1083)
Integer underflow in the isakmp_id_print allows remote attackers to cause
a denial of service (crash) via an ISAKMP packet with an Identification
payload with a length that becomes less than 8 during byte order
conversion, which causes an out-of-bounds read. (CVE-2004-0184)
The updated packages are patched to correct these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:030");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0183", "CVE-2004-0184", "CVE-2004-1083");
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

if ( rpm_check( reference:"tcpdump-3.8.1-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK10.0")
 || rpm_exists(rpm:"tcpdump-", release:"MDK9.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0183", value:TRUE);
 set_kb_item(name:"CVE-2004-0184", value:TRUE);
 set_kb_item(name:"CVE-2004-1083", value:TRUE);
}
exit(0, "Host is not affected");
