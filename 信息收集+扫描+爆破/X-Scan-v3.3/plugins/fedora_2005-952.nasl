#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19971);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Fedora Core 4 2005-952: w3c-libwww";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-952 (w3c-libwww).

Libwww is a general-purpose Web API written in C for Unix and Windows (Win32).
With a highly extensible and layered API, it can accommodate many different
types of applications including clients, robots, etc. The purpose of libwww
is to provide a highly optimized HTTP sample implementation as well as other
Internet protocols and to serve as a testbed for protocol experiments.

Update Information:

This update fixes libwww's handling of multipart/byteranges
content and a possible stack overflow." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the w3c-libwww package";
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
if ( rpm_check( reference:"w3c-libwww-5.4.0-13.0.FC4.1", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
