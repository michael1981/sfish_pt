
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14120);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:021: mozilla");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:021 (mozilla).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in Mozilla 1.4:
A malicious website could gain access to a user's authentication
credentials to a proxy server.
Script.prototype.freeze/thaw could allow an attacker to run
arbitrary code on your computer.
A vulnerability was also discovered in the NSS security suite which
ships with Mozilla. The S/MIME implementation would allow remote
attackers to cause a Denial of Service and possibly execute arbitrary
code via an S/MIME email message containing certain unexpected ASN.1
constructs, which was demonstrated using the NISCC test suite. NSS
version 3.9 corrects these problems and has been included in this
package (which shipped with NSS 3.8).
Finally, Corsaire discovered that a number of HTTP user agents
contained a flaw in how they handle cookies. This flaw could
allow an attacker to avoid the path restrictions specified by a
cookie's originator. According to their advisory:
'The cookie specifications detail a path argument that can be used to
restrict the areas of a host that will be exposed to a cookie. By
using standard traversal techniques this functionality can be
subverted, potentially exposing the cookie to scrutiny and use in
further attacks.'
As well, a bug with Mozilla and Finnish keyboards has been corrected.
The updated packages are patched to correct these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:021");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0564", "CVE-2003-0594");
script_summary(english: "Check for the version of the mozilla package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libnspr4-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmail-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmime-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.4-13.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0564", value:TRUE);
 set_kb_item(name:"CVE-2003-0594", value:TRUE);
}
exit(0, "Host is not affected");
