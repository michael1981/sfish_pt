
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-540
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25358);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2007-540: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-540 (mutt)");
 script_set_attribute(attribute: "description", value: "Mutt is a text-mode mail user agent. Mutt supports color, threading,
arbitrary key remapping, and a lot of customization.

You should install mutt if you have used it in the past and you prefer
it, or if you are new to mail programs and have not decided which one
you are going to use.

Update Information:

This update fixes two security issues:

The APOP protocol allows remote attackers to guess the first
3 characters of a password via man-in-the-middle (MITM)
attacks that use crafted message IDs and MD5 collisions.
(CVE-2007-1558)

Buffer overflow in Mutt 1.4.2 might allow local users to
execute arbitrary code via '&' characters in the GECOS
field, which triggers the overflow during alias expansion.
(CVE-2007-2683)


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-3242", "CVE-2006-5297", "CVE-2007-1558", "CVE-2007-2683");
script_summary(english: "Check for the version of the mutt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mutt-1.4.2.1-8.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
