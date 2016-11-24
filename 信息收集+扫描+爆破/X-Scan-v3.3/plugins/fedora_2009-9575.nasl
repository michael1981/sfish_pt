
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9575
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40993);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 11 2009-9575: planet");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9575 (planet)");
 script_set_attribute(attribute: "description", value: "Planet is a flexible feed aggregator, this means that it downloads feeds
and aggregates their content together into a single combined feed with
the latest news first.

It uses Mark Pilgrim's Ultra-liberal feed parser so can read from RDF, RSS
and Atom feeds and Tomas Styblo's template library to output static files
in unlimited formats based on a series of templates.

-
Update Information:

Security update for sanitizing input from rss feeds.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2937");
script_summary(english: "Check for the version of the planet package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"planet-2.0-10.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
