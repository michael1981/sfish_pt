
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1204
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37289);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-1204: roundcubemail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1204 (roundcubemail)");
 script_set_attribute(attribute: "description", value: "RoundCube Webmail is a browser-based multilingual IMAP client
with an application-like user interface. It provides full
functionality you expect from an e-mail client, including MIME
support, address book, folder manipulation, message searching
and spell checking. RoundCube Webmail is written in PHP and
requires the MySQL database or the PostgreSQL database. The user
interface is fully skinnable using XHTML and CSS 2.

-
Update Information:

Security fix for:    Common Vulnerabilities and Exposures assigned an identifie
r
CVE-2009-0413 to  the following vulnerability:    Cross-site scripting (XSS)
vulnerability in RoundCube Webmail  (roundcubemail) 0.2 stable allows remote
attackers to inject arbitrary  web script or HTML via the background attribute
embedded in an HTML  e-mail message.    References:  [9]http://cve.mitre.org/cg
i-
bin/cvename.cgi?name=CVE-2009-0413  [10]http://trac.roundcube.net/changeset/224
5
[11]http://www.securityfocus.com/bid/33372  [12]http://secunia.com/advisories/3
3622
[13]http://xforce.iss.net/xforce/xfdb/48129
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0413");
script_summary(english: "Check for the version of the roundcubemail package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"roundcubemail-0.2-7.stable.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
