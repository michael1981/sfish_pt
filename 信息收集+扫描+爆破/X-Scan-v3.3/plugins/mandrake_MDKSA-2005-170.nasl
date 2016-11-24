
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19923);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:170: mozilla");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:170 (mozilla).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities have been discovered in Mozilla that have
been corrected in version 1.7.12:
A bug in the way Mozilla processes XBM images could be used to execute
arbitrary code via a specially crafted XBM image file (CVE-2005-2701).
A bug in the way Mozilla handles certain Unicode sequences could be
used to execute arbitrary code via viewing a specially crafted Unicode
sequence (CVE-2005-2702).
A bug in the way Mozilla makes XMLHttp requests could be abused by a
malicious web page to exploit other proxy or server flaws from the
victim's machine; however, the default behaviour of the browser is to
disallow this (CVE-2005-2703).
A bug in the way Mozilla implemented its XBL interface could be abused
by a malicious web page to create an XBL binding in such a way as to
allow arbitrary JavaScript execution with chrome permissions
(CVE-2005-2704).
An integer overflow in Mozilla's JavaScript engine could be manipulated
in certain conditions to allow a malicious web page to execute
arbitrary code (CVE-2005-2705).
A bug in the way Mozilla displays about: pages could be used to execute
JavaScript with chrome privileges (CVE-2005-2706).
A bug in the way Mozilla opens new windows could be used by a malicious
web page to construct a new window without any user interface elements
(such as address bar and status bar) that could be used to potentially
mislead the user (CVE-2005-2707).
Tom Ferris reported that Firefox would crash when processing a domain
name consisting solely of soft-hyphen characters due to a heap overflow
when IDN processing results in an empty string after removing non-
wrapping chracters, such as soft-hyphens. This could be exploited to
run or or install malware on the user's computer (CVE-2005-2871).
The updated packages have been patched to address these issues and all
users are urged to upgrade immediately.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:170");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871");
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

if ( rpm_check( reference:"libnspr4-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmail-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-enigmime-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-0.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-2701", value:TRUE);
 set_kb_item(name:"CVE-2005-2702", value:TRUE);
 set_kb_item(name:"CVE-2005-2703", value:TRUE);
 set_kb_item(name:"CVE-2005-2704", value:TRUE);
 set_kb_item(name:"CVE-2005-2705", value:TRUE);
 set_kb_item(name:"CVE-2005-2706", value:TRUE);
 set_kb_item(name:"CVE-2005-2707", value:TRUE);
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
}
exit(0, "Host is not affected");
