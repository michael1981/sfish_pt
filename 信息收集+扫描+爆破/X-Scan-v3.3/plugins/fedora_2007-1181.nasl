
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1181
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27706);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1181: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1181 (seamonkey)");
 script_set_attribute(attribute: "description", value: "SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

-
Update Information:

SeaMonkey is an open source Web browser, advanced email and newsgroup client, I
RC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processed certain malformed JavaS
cript code. A web page containing malicious JavaScript code could cause SeaMonk
ey to crash or potentially execute arbitrary code as the user running SeaMonkey
. (CVE-2007-3734, CVE-2007-3735, CVE-2007-3737, CVE-2007-3738)

Several content injection flaws were found in the way SeaMonkey handled certain
JavaScript code. A web page containing malicious JavaScript code could inject
arbitrary content into other web pages. (CVE-2007-3736, CVE-2007-3089)

A flaw was found in the way SeaMonkey cached web pages on the local disk. A mal
icious web page may be able to inject arbitrary HTML into a browsing session if
the user reloads a targeted site. (CVE-2007-3656)

Users of SeaMonkey are advised to upgrade to these erratum packages, which cont
ain patches that correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
script_summary(english: "Check for the version of the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"seamonkey-1.1.3-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
