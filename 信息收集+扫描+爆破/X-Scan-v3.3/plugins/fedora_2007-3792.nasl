
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3792
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28342);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 7 2007-3792: blam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3792 (blam)");
 script_set_attribute(attribute: "description", value: "Blam is a tool that helps you keep track of the growing
number of news feeds distributed as RSS. Blam lets you
subscribe to any number of feeds and provides an easy to
use and clean interface to stay up to date

-
Update Information:

This update resolves a low severity security issue where LD_LIBRARY_PATH could
potentially get set to the current directory if it wasn't set before Blam was l
aunched.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-4790");
script_summary(english: "Check for the version of the blam package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"blam-1.8.3-9.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
