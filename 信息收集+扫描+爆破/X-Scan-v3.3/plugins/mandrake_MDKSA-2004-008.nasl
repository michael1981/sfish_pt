
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14108);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2004:008: tcpdump");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:008 (tcpdump).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in tcpdump versions prior
to 3.8.1 that, if fed a maliciously crafted packet, could be exploited
to crash tcpdump or potentially execute arbitrary code with the
privileges of the user running tcpdump. These vulnerabilities include:
An infinite loop and memory consumption processing L2TP packets
(CVE-2003-1029).
Infinite loops in processing ISAKMP packets (CVE-2003-0989,
CVE-2004-0057).
A segmentation fault caused by a RADIUS attribute with a large length
value (CVE-2004-0055).
The updated packages are patched to correct these problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:008");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0055", "CVE-2004-0057");
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

if ( rpm_check( reference:"tcpdump-3.7.2-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK9.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0989", value:TRUE);
 set_kb_item(name:"CVE-2003-1029", value:TRUE);
 set_kb_item(name:"CVE-2004-0055", value:TRUE);
 set_kb_item(name:"CVE-2004-0057", value:TRUE);
}
exit(0, "Host is not affected");
