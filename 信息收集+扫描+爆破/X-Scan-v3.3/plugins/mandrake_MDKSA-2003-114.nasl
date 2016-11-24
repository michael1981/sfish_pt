
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14096);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:114: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:114 (ethereal).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in ethereal that, if
exploited, could be used to make ethereal crash or run arbitrary code
by injecting malicious malformed packets onto the wire or by
convincing someone to read a malformed packet trace file.
A buffer overflow allows attackers to cause a DoS (Denial of Service)
and possibly execute arbitrary code using a malformed GTP MSISDN
string (CVE-2003-0925).
Likewise, a DoS can be caused by using malformed ISAKMP or MEGACO
packets (CVE-2003-0926).
Finally, a heap-based buffer overflow allows attackers to cause a DoS
or execute arbitrary code using the SOCKS dissector (CVE-2003-0927).
All three vulnerabilities affect all versions of Ethereal up to and
including 0.9.15. This update provides 0.9.16 which corrects all of
these issues. Also note that each vulnerability can be exploited by
a remote attacker.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:114");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0925", "CVE-2003-0926", "CVE-2003-0927");
script_summary(english: "Check for the version of the ethereal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.9.16-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.9.16-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0925", value:TRUE);
 set_kb_item(name:"CVE-2003-0926", value:TRUE);
 set_kb_item(name:"CVE-2003-0927", value:TRUE);
}
exit(0, "Host is not affected");
