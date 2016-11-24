#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13730);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Fedora Core 2 2004-176: libpng10";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-176 (libpng10).

The libpng10 package contains an old version of libpng, a library of
functions for creating and manipulating PNG (Portable Network Graphics)
image format files.

This package is needed if you want to run binaries that were linked
dynamically
with libpng 1.0.x.

Update Information:

During an audit of Red Hat Linux updates, the Fedora Legacy team found a
security issue in libpng that had not been fixed in Fedora Core. An
attacker could carefully craft a PNG file in such a way that
it would cause an application linked to libpng to crash or potentially
execute arbitrary code when opened by a victim." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-176.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the libpng10 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"libpng10-1.0.15-5", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.15-5", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng10-debuginfo-1.0.15-5", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
