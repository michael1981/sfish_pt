
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2062
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31812);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2062: konversation");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2062 (konversation)");
 script_set_attribute(attribute: "description", value: "A simple and easy to use IRC client for KDE with support for
strikeout; multi-channel joins; away / unaway messages;
ignore list functionality; (experimental) support for foreign
language characters; auto-connect to server; optional timestamps
to chat windows; configurable background colors and much more

-
Update Information:

removes /usr/share/apps/konversation/scripts/media  which can be used to execut
e
a command via carefully crafted media
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4400");
script_summary(english: "Check for the version of the konversation package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"konversation-1.0.1-4.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
