
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18498);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:101: tcpdump");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:101 (tcpdump).");
 script_set_attribute(attribute: "description", value: "A Denial of Service vulnerability was found in tcpdump during the
processing of certain network packages. Because of this flaw, it was
possible for an attacker to inject a carefully crafted packet onto the
network which would crash a running tcpdump session.
The updated packages have been patched to correct this problem. This
problem does not affect at least tcpdump 3.8.1 and earlier.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:101");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1267");
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

if ( rpm_check( reference:"tcpdump-3.8.3-2.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.8.3-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"MDK10.1")
 || rpm_exists(rpm:"tcpdump-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1267", value:TRUE);
}
exit(0, "Host is not affected");
