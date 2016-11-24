
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-552
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25378);
 script_version ("$Revision: 1.5 $");
script_name(english: "Fedora 5 2007-552: yelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-552 (yelp)");
 script_set_attribute(attribute: "description", value: "Yelp is the Gnome 2 help/documentation browser. It is designed
to help you browse all the documentation on your system in
one central tool.

Update Information:

Updated seamonkey packages that fix several security bugs
are now available for Fedora Core 5.

This update has been rated as having critical security
impact by the Fedora Security Response Team.

SeaMonkey is an open source Web browser, advanced email and
newsgroup client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processed
certain malformed JavaScript code. A web page containing
malicious JavaScript code could cause SeaMonkey to crash or
potentially execute arbitrary code as the user running
SeaMonkey. (CVE-2007-2867, CVE-2007-2868)

A flaw was found in the way SeaMonkey handled certain FTP
PASV commands. A malicious FTP server could use this flaw to
perform a rudimentary port-scan of machines behind a user's
firewall. (CVE-2007-1562)

Several denial of service flaws were found in the way
SeaMonkey handled certain form and cookie data. A malicious
web site that is able to set arbitrary form and cookie data
could prevent SeaMonkey from functioning properly.
(CVE-2007-1362, CVE-2007-2869)

A flaw was found in the way SeaMonkey processed certain APOP
authentication requests. By sending certain responses when
SeaMonkey attempted to authenticate against an APOP server,
a remote attacker could potentially acquire certain portions
of a user's authentication credentials. (CVE-2007-1558)

A flaw was found in the way SeaMonkey handled the
addEventListener JavaScript method. A malicious web site
could use this method to access or modify sensitive data
from another web site. (CVE-2007-2870)

A flaw was found in the way SeaMonkey displayed certain web
content. A malicious web page could generate content that
would overlay user interface elements such as the hostname
and security indicators, tricking users into thinking they
are visiting a different site. (CVE-2007-2871)

Users of SeaMonkey are advised to upgrade to these erratum
packages, which contain SeaMonkey version 1.0.9 that
corrects these issues.


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1558", "CVE-2007-1562", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
script_summary(english: "Check for the version of the yelp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"yelp-2.14.3-5.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
