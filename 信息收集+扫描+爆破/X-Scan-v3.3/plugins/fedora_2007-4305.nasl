
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4305
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29282);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-4305: eggdrop");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4305 (eggdrop)");
 script_set_attribute(attribute: "description", value: "Eggdrop is the world's most popular Open Source IRC bot, designed
for flexibility and ease of use. It is extendable with Tcl scripts
and/or C modules, has support for the big five IRC networks and is
able to form botnets, share partylines and userfiles between bots.

-
Update Information:

Added a patch to fix some stack based overflows (CVE-2007-2807)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2807");
script_summary(english: "Check for the version of the eggdrop package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"eggdrop-1.6.18-12.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
