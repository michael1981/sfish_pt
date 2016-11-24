
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7750
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39860);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-7750: mediawiki");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7750 (mediawiki)");
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

This update upgrades mediawiki code to 1.15.1 and fixes some path references.
Upstream comments:  This is a security and bugfix release of MediaWiki 1.15.1
and 1.14.1.    A cross-site scripting (XSS) vulnerability was discovered. Only
versions 1.14.0, 1.15.0 and release candidates for those releases are affected.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5249", "CVE-2008-5688");
script_summary(english: "Check for the version of the mediawiki package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mediawiki-1.15.1-48.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
