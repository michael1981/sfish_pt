
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6491
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33539);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-6491: Miro");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6491 (Miro)");
 script_set_attribute(attribute: "description", value: "Miro is a free application that turns your computer into an
internet TV video player. This release is still a beta version, which means
that there are some bugs, but we're moving quickly to fix them and will be
releasing bug fixes on a regular basis.

-
Update Information:

Updated firefox packages that fix several security issues are now available for
Fedora 8.    An integer overflow flaw was found in the way Firefox displayed
certain web content. A malicious web site could cause Firefox to crash, or
execute arbitrary code with the permissions of the user running Firefox.
(CVE-2008-2785)    A flaw was found in the way Firefox handled certain command
line URLs. If another application passed Firefox a malformed URL, it could
result in Firefox executing local malicious content with chrome privileges.
(CVE-2008-2933)    Updated packages update Mozilla Firefox to upstream version
2.0.0.16 to address these flaws:    [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox20.html#firefox2.0.0.16    This update also contains
blam, cairo-dock, chmsee, devhelp, epiphany, epiphany-extensions, galeon, gnome
-
python2-extras, gnome-web-photo, gtkmozembedmm, kazehakase, liferea, Miro,
openvrml, ruby-gnome2 and yelp packages rebuilt against new Firefox / Gecko
libraries.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2785", "CVE-2008-2933");
script_summary(english: "Check for the version of the Miro package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"Miro-1.2.3-3.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
