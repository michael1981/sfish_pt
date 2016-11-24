
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20057);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2005:186-1: lynx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:186-1 (lynx).");
 script_set_attribute(attribute: "description", value: "Ulf Harnhammar discovered a remote buffer overflow in lynx versions
2.8.2 through 2.8.5.
When Lynx connects to an NNTP server to fetch information about the
available articles in a newsgroup, it will call a function called
HTrjis() with the information from certain article headers. The
function adds missing ESC characters to certain data, to support
Asian character sets. However, it does not check if it writes outside
of the char array buf, and that causes a remote stack-based buffer
overflow, with full control over EIP, EBX, EBP, ESI and EDI.
Two attack vectors to make a victim visit a URL to a dangerous news
server are: (a) *redirecting scripts*, where the victim visits some
web page and it redirects automatically to a malicious URL, and
(b) *links in web pages*, where the victim visits some web page
and selects a link on the page to a malicious URL. Attack vector
(b) is helped by the fact that Lynx does not automatically display
where links lead to, unlike many graphical web browsers.
The updated packages have been patched to address this issue.
Update:
The previous patchset had a bug in the patches themselves, which was
uncovered by Klaus Singvogel of Novell/SUSE in auditing crashes on
some architectures.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:186-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3120");
script_summary(english: "Check for the version of the lynx package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lynx-2.8.5-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"lynx-", release:"MDK10.1")
 || rpm_exists(rpm:"lynx-", release:"MDK10.2")
 || rpm_exists(rpm:"lynx-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3120", value:TRUE);
}
exit(0, "Host is not affected");
