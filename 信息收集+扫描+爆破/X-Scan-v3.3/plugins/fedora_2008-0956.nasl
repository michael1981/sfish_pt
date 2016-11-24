
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-0956
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30083);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-0956: xorg-x11-server");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-0956 (xorg-x11-server)");
 script_set_attribute(attribute: "description", value: "X.Org X11 X server

-
Update Information:

When enabling the 'unredirect fullscreen windows' option, compiz will unredirec
t fullscreen windows to improve performace.  However, unredirecting will as a s
ide effect break any grabs on that window, which compromises most screensavers.
This X server update suppresses this unintended side effect and restores the
security of the screensavers.  See also CVE-2007-3069.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3069", "CVE-2007-3920");
script_summary(english: "Check for the version of the xorg-x11-server package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xorg-x11-server-1.3.0.0-16.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
