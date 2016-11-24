
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3962
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28347);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-3962: ruby-gnome2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3962 (ruby-gnome2)");
 script_set_attribute(attribute: "description", value: "This is a set of bindings for the GNOME-2.x libraries for use from Ruby.

-
Update Information:

Updated firefox packages that fix several security issues are now available for
Fedora 8.

This update has been rated as having critical security impact by the Fedora Sec
urity Response Team.

Mozilla Firefox is an open source Web browser.

A cross-site scripting flaw was found in the way Firefox handled the jar: URI s
cheme. It was possible for a malicious website to leverage this flaw and conduc
t a cross-site scripting attack against a user running Firefox. (CVE-2007-5947)

Several flaws were found in the way Firefox processed certain malformed web con
tent. A webpage containing malicious content could cause Firefox to crash, or p
otentially execute arbitrary code as the user running Firefox. (CVE-2007-5959)

A race condition existed when Firefox set the 'window.location' property for a
webpage. This flaw could allow a webpage to set an arbitrary Referer header, wh
ich may lead to a Cross-site Request Forgery (CSRF) attack against websites tha
t rely only on the Referer header for protection. (CVE-2007-5960)

Users of Firefox are advised to upgrade to these updated packages, which contai
n backported patches to resolve these issues.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
script_summary(english: "Check for the version of the ruby-gnome2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ruby-gnome2-0.16.0-17.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
