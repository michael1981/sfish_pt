
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14011);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:027: tcpdump");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:027 (tcpdump).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered by Andrew Griffiths and iDEFENSE Labs
in the tcpdump program. By sending a specially crafted network packet,
an attacker is able to to cause tcpdump to enter an infinite loop. In
addition, the tcpdump developers found a potential infinite loop when
tcpdump parses malformed BGP packets. A buffer overflow was also
discovered that can be exploited with certain malformed NFS packets.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:027");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1350", "CVE-2003-0093", "CVE-2003-0108", "CVE-2003-0145");
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

if ( rpm_check( reference:"libpcap0-0.7.2-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.7.2-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap0-0.7.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.7.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap0-0.7.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap0-devel-0.7.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK8.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK8.2")
 || rpm_exists(rpm:"tcpdump-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1350", value:TRUE);
 set_kb_item(name:"CVE-2003-0093", value:TRUE);
 set_kb_item(name:"CVE-2003-0108", value:TRUE);
 set_kb_item(name:"CVE-2003-0145", value:TRUE);
}
exit(0, "Host is not affected");
