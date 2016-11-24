
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1442
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27715);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1442: mediawiki");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1442 (mediawiki)");
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

This update fixes the following vulnerability:

'Cross-site scripting (XSS) vulnerability in the AJAX features in
index.php in MediaWiki 1.6.x through 1.9.2, when $wgUseAjax is
enabled, allows remote attackers to inject arbitrary web script
or HTML via a UTF-7 encoded value of the rs parameter, which is
processed by Internet Explorer.'

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1054");
script_summary(english: "Check for the version of the mediawiki package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mediawiki-1.9.3-34.0.2.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
