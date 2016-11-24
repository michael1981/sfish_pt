
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2853
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27810);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-2853: liferea");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2853 (liferea)");
 script_set_attribute(attribute: "description", value: "Liferea (Linux Feed Reader) is an RSS/RDF feed reader.
It's intended to be a clone of the Windows-only FeedReader.
It can be used to maintain a list of subscribed feeds,
browse through their items, and show their contents.

-
Update Information:

Added patch to fix weak permission in feedlist.opml backup file.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5751");
script_summary(english: "Check for the version of the liferea package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"liferea-1.2.23-5.fc8", release:"FC8") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
