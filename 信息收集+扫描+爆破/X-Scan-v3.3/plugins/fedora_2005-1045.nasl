#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20138);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CAN-2005-2974");
 
 name["english"] = "Fedora Core 3 2005-1045: libungif";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-1045 (libungif).

The libungif package contains a shared library of functions for
loading and saving GIF format image files.  The libungif library can
load any GIF file, but it will save GIFs only in uncompressed format
(i.e., it won't use the patented LZW compression used to save 'normal'
compressed GIF files).

Install the libungif package if you need to manipulate GIF files.  You
should also install the libungif-progs package.

Update Information:

The libungif package contains a shared library of functions
for loading and saving GIF format image files. The libungif
library can load any GIF file, but it will save GIFs only in
uncompressed format; it will not use the patented LZW
compression used to save 'normal' compressed GIF files.

A bug was found in the way libungif handles colormaps. An
attacker could create a GIF file in such a way that could
cause out-of-bounds writes and register corruptions. The
Common Vulnerabilities and Exposures project assigned the
name CAN-2005-2974 to this issue.

All users of libungif should upgrade to the updated
packages, which contain a backported patch to resolve this
issue." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the libungif package";
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
if ( rpm_check( reference:"libungif-4.1.3-1.fc3.2", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libungif-devel-4.1.3-1.fc3.2", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.3-1.fc3.2", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"libungif-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-2974", value:TRUE);
}
