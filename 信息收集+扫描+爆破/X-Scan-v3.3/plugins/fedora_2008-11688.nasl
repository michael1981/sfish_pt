
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11688
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35265);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-11688: mediawiki");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11688 (mediawiki)");
 script_set_attribute(attribute: "description", value: "MediaWiki is the software used for Wikipedia and the other Wikimedia
Foundation websites. Compared to other wikis, it has an excellent
range of features and support for high-traffic websites using multiple
servers

This package supports wiki farms. Copy /var/www/wiki over to the
desired wiki location and configure it through the web
interface. Remember to remove the config dir after completing the
configuration.

-
Update Information:

This is a security release of MediaWiki 1.13.3.    Some of the security issues
affect *all* versions of MediaWiki except the versions released on Dec. 15th, s
o
all site administrators are encouraged to upgrade.    CVEs assigned to the
mentioned MediaWiki update:    CVE-2008-5249  Cross-site scripting (XSS)
vulnerability in MediaWiki 1.13.0 through 1.13.2 allows remote attackers to
inject arbitrary web script or HTML via unspecified vectors.    CVE-2008-5250
Cross-site scripting (XSS) vulnerability in MediaWiki before 1.6.11, 1.12.x
before 1.12.2, and 1.13.x before 1.13.3, when Internet Explorer is used and
uploads are enabled, or an SVG scripting browser is used and SVG uploads are
enabled, allows remote authenticated users to inject arbitrary web script or
HTML by editing a wiki page.    CVE-2008-5252  Cross-site request forgery (CSRF
)
vulnerability in the Special:Import feature in MediaWiki 1.3.0 through 1.6.10,
1.12.x before 1.12.2, and 1.13.x before 1.13.3 allows remote attackers to
perform unspecified actions as authenticated users via unknown vectors.    As
well as other two issue mentioned in the upstream announcement, treated as
security enhancement rather than vulnerability fixes by upstream:
CVE-2008-5687  MediaWiki 1.11 through 1.13.3 does not properly protect against
the download of backups of deleted images, which might allow remote attackers t
o
obtain sensitive information via requests for files in images/deleted/.
CVE-2008-5688  MediaWiki 1.8.1 through 1.13.3, when the wgShowExceptionDetails
variable is enabled, sometimes provides the full installation path in a
debugging message, which might allow remote attackers to obtain sensitive
information via unspecified requests that trigger an uncaught exception.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0460", "CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2008-5687", "CVE-2008-5688");
script_summary(english: "Check for the version of the mediawiki package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mediawiki-1.13.3-41.99.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
