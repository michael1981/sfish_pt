
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20428);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:174: mozilla-thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:174 (mozilla-thunderbird).");
 script_set_attribute(attribute: "description", value: "Updated Mozilla Thunderbird packages fix various vulnerabilities:
The run-mozilla.sh script, with debugging enabled, would allow local
users to create or overwrite arbitrary files via a symlink attack on
temporary files (CVE-2005-2353).
A bug in the way Thunderbird processes XBM images could be used to
execute arbitrary code via a specially crafted XBM image file
(CVE-2005-2701).
A bug in the way Thunderbird handles certain Unicode sequences could be
used to execute arbitrary code via viewing a specially crafted Unicode
sequence (CVE-2005-2702).
A bug in the way Thunderbird makes XMLHttp requests could be abused by
a malicious web page to exploit other proxy or server flaws from the
victim's machine; however, the default behaviour of the browser is to
disallow this (CVE-2005-2703).
A bug in the way Thunderbird implemented its XBL interface could be
abused by a malicious web page to create an XBL binding in such a way
as to allow arbitrary JavaScript execution with chrome permissions
(CVE-2005-2704).
An integer overflow in Thunderbird's JavaScript engine could be
manipulated in certain conditions to allow a malicious web page to
execute arbitrary code (CVE-2005-2705).
A bug in the way Thunderbird displays about: pages could be used to
execute JavaScript with chrome privileges (CVE-2005-2706).
A bug in the way Thunderbird opens new windows could be used by a
malicious web page to construct a new window without any user interface
elements (such as address bar and status bar) that could be used to
potentially mislead the user (CVE-2005-2707).
A bug in the way Thunderbird proceesed URLs on the command line could
be used to execute arbitary commands as the user running Thunderbird;
this could be abused by clicking on a supplied link, such as from an
instant messaging client (CVE-2005-2968).
Tom Ferris reported that Thunderbird would crash when processing a
domain name consisting solely of soft-hyphen characters due to a heap
overflow when IDN processing results in an empty string after removing
non-wrapping chracters, such as soft-hyphens. This could be exploited
to run or or install malware on the user's computer (CVE-2005-2871).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:174");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2353", "CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
script_summary(english: "Check for the version of the mozilla-thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mozilla-thunderbird-1.0.2-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-devel-1.0.2-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-1.0.2-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmime-1.0.2-5.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-1.0.6-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmail-1.0.6-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-thunderbird-enigmime-1.0.6-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK10.2")
 || rpm_exists(rpm:"mozilla-thunderbird-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2353", value:TRUE);
 set_kb_item(name:"CVE-2005-2701", value:TRUE);
 set_kb_item(name:"CVE-2005-2702", value:TRUE);
 set_kb_item(name:"CVE-2005-2703", value:TRUE);
 set_kb_item(name:"CVE-2005-2704", value:TRUE);
 set_kb_item(name:"CVE-2005-2705", value:TRUE);
 set_kb_item(name:"CVE-2005-2706", value:TRUE);
 set_kb_item(name:"CVE-2005-2707", value:TRUE);
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
 set_kb_item(name:"CVE-2005-2968", value:TRUE);
}
exit(0, "Host is not affected");
