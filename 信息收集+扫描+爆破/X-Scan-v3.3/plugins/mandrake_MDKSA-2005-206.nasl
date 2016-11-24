
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20440);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:206-1: openvpn");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:206-1 (openvpn).");
 script_set_attribute(attribute: "description", value: "Two Denial of Service vulnerabilities exist in OpenVPN. The first
allows a malicious or compromised server to execute arbitrary code
on the client (CVE-2005-3393). The second DoS can occur if when in
TCP server mode, OpenVPN received an error on accept(2) and the
resulting exception handler causes a segfault (CVE-2005-3409).
The updated packages have been patched to correct these problems.
Update:
Packages are now available for Mandriva Linux 2006.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:206-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3393", "CVE-2005-3409");
script_summary(english: "Check for the version of the openvpn package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openvpn-2.0.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openvpn-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3393", value:TRUE);
 set_kb_item(name:"CVE-2005-3409", value:TRUE);
}
exit(0, "Host is not affected");
