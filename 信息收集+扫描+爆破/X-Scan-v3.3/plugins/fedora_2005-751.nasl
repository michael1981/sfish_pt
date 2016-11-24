#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19660);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");
 
 name["english"] = "Fedora Core 4 2005-751: gaim";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-751 (gaim).

Gaim is a clone of America Online's Instant Messenger client. It
features nearly all of the functionality of the official AIM client
while also being smaller, faster, and commercial-free.

Update Information:

[14]http://gaim.sourceforge.net/
Please see the Changelog details and security information at
the upstream Gaim Project site." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the gaim package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gaim-1.5.0-1.fc4", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"gaim-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2102", value:TRUE);
 set_kb_item(name:"CVE-2005-2103", value:TRUE);
 set_kb_item(name:"CVE-2005-2370", value:TRUE);
}
