
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10445
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42126);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-10445: drupal-service_links");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10445 (drupal-service_links)");
 script_set_attribute(attribute: "description", value: "The service links module enables admins to add links to a number of social
bookmarking sites, blog search sites etc. Includes sites are del.icio.us,
Digg, Reddit, ma.gnolia.com, Newsvine, Furl, Google, Yahoo, Technorati and
IceRocket.

-
Update Information:

Common Vulnerabilities and Exposures assigned an identifier CVE-2009-3648 to
the following vulnerability:    Name: CVE-2009-3648  URL: [9]http://cve.mitre.o
rg
/cgi-bin/cvename.cgi?name=CVE-2009-3648  Assigned: 20091009  Reference: MISC:
[10]http://www.madirish.net/?article=251  Reference: BID:36584  Reference: URL:
[11]http://www.securityfocus.com/bid/36584  Reference: XF:servicelinks-content-
type-
xss(53633)  Reference: URL: [12]http://xforce.iss.net/xforce/xfdb/53633    Cros
s-
site scripting (XSS) vulnerability in Service Links 6.x-1.0, a  module for
Drupal, allows remote authenticated users, with 'administer  content types'
permissions, to inject arbitrary web script or HTML via  unspecified vectors
when displaying content type names.      Checked drupal-service_links in CVS an
d
this affects Fedora 10, 11, and  rawhide.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3648");
script_summary(english: "Check for the version of the drupal-service_links package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-service_links-6.x.1.0-5.fc10", release:"FC10") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
