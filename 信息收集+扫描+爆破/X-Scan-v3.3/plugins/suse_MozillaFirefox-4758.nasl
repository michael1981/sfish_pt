
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28369);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox: Security update to version 2.0.0.10 (MozillaFirefox-4758)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-4758");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Firefox to security update
version 2.0.0.10

Following security problems were fixed: MFSA 2007-37 /
CVE-2007-5947: The jar protocol handler in Mozilla Firefox
retrieves the inner URL regardless of its MIME type, and
considers HTML documents within a jar archive to have the
same origin as the inner URL, which allows remote attackers
to conduct cross-site scripting (XSS) attacks via a jar:
URI.

MFSA 2007-38 / CVE-2007-5959:  The Firefox 2.0.0.10 update
contains fixes for three bugs that improve the stability of
the product. These crashes showed some evidence of memory
corruption under certain circumstances and we presume that
with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2007-39 / CVE-2007-5960: Gregory Fleischer
demonstrated that it was possible to generate a fake HTTP
Referer header by exploiting a timing condition when
setting the window.location property. This could be used to
conduct a Cross-site Request Forgery (CSRF) attack against
websites that rely only on the Referer header as protection
against such attacks.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-4758");
script_end_attributes();

script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
script_summary(english: "Check for the MozillaFirefox-4758 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-2.0.0.10-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.10-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
