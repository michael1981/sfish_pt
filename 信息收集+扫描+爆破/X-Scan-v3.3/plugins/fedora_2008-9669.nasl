
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9669
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34778);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-9669: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9669 (devhelp)");
 script_set_attribute(attribute: "description", value: "An API document browser for GNOME 2.

-
Update Information:

Updated firefox and xulrunner packages that fix various security issues are now
available for Fedora Core 9.    This update has been rated as having critical
security impact by the Fedora Security Response Team.    Mozilla Firefox is an
open source Web browser.    Several flaws were found in the processing of
malformed web content. A web page containing malicious content could cause
Firefox to crash or, potentially, execute arbitrary code as the user running
Firefox. (CVE-2008-0017, CVE-2008-5014, CVE-2008-5016, CVE-2008-5017,
CVE-2008-5018, CVE-2008-5019, CVE-2008-5021)    Several flaws were found in the
way malformed content was processed. A web site containing specially-crafted
content could potentially trick a Firefox user into surrendering sensitive
information. (CVE-2008-5022, CVE-2008-5023, CVE-2008-5024)    A flaw was found
in the way Firefox opened 'file:' URIs. If a file: URI was loaded in the same
tab as a chrome or privileged 'about:' page, the file: URI could execute
arbitrary code with the permissions of the user running Firefox. (CVE-2008-5015
)
For technical details regarding these flaws, please see the Mozilla security
advisories for Firefox 3.0.4[1].    All firefox users and users of packages
depending on xulrunner[2] should upgrade to these updated packages, which
contain patches that correct these issues.    [1]
[9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.4  [2] cairo-dock chmsee devhelp
epiphany epiphany-extensions evolution-rss galeon gnome-python2-extras gnome-
web-photo google-gadgets gtkmozembedmm kazehakase Miro mozvoikko mugshot ruby-
gnome2 totem yelp  Provides Python bindings for libgdl on PPC64.  This update
fixes a build break.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
script_summary(english: "Check for the version of the devhelp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"devhelp-0.19.1-6.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
