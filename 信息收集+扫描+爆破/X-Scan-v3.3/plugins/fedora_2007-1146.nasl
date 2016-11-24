
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1146
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27697);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-1146: liferea");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1146 (liferea)");
 script_set_attribute(attribute: "description", value: "Liferea (Linux Feed Reader) is an RSS/RDF feed reader.
It's intended to be a clone of the Windows-only FeedReader.
It can be used to maintain a list of subscribed feeds,
browse through their items, and show their contents.

-
Update Information:

Rebuild for new gecko-libs 1.8.1.5.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the liferea package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"liferea-1.2.19-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
