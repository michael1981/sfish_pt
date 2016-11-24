#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19624);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Fedora Core 2 2005-202: grip";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-202 (grip).

Grip is a GTK+ based front-end for CD rippers (such as cdparanoia and
cdda2wav) and Ogg Vorbis encoders.  Grip allows you to rip entire tracks or
just a section of a track.  Grip supports the CDDB protocol for
accessing track information on disc database servers.

Update Information:

This fixes a buffer overflow when the CDDB server returns more than 16
matches." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the grip package";
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
if ( rpm_check( reference:"grip-3.2.0-3.fc2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
