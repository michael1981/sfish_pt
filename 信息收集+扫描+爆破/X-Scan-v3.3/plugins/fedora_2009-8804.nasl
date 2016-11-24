
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8804
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40682);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 11 2009-8804: farsight2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8804 (farsight2)");
 script_set_attribute(attribute: "description", value: "farsight2 is a collection of GStreamer modules and libraries for
videoconferencing.

-
Update Information:

pidgin upgrade to 2.6.0 for the CVE-2009-2694, insufficient input validation in
msn_slplink_process_msg().  2.6.0 has Voice and Video support via farsight2
(Fedora 11+ only) and numerous other bug fixes.    farsight2, libnice and gupnp
-
igd are version upgrades to make voice and video actually work on Fedora 11.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2694");
script_summary(english: "Check for the version of the farsight2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"farsight2-0.0.14-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
