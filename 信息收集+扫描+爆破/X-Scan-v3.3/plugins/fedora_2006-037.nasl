#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20730);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CAN-2005-3193");
 
 name["english"] = "Fedora Core 4 2006-037: kdegraphics";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2006-037 (kdegraphics).

Graphics applications for the K Desktop Environment.

Includes:
kdvi (displays TeX .dvi files)
kfax (displays faxfiles)
kghostview (displays postscript files)
kcoloredit (palette editor and color chooser)
kamera (digital camera support)
kiconedit (icon editor)
kpaint (a simple drawing program)
ksnapshot (screen capture utility)
kview (image viewer for GIF, JPEG, TIFF, etc.)
kuickshow (quick picture viewer)
kooka (scanner application)
kruler (screen ruler and color measurement tool)

Update Information:

Several flaws were discovered in Xpdf. An attacker could
construct a carefully crafted PDF file that could cause xpdf
to crash or possibly execute arbitrary code when opened. The
Common Vulnerabilities and Exposures project assigned the
name CAN-2005-3193 to these issues.

Users of kdegraphics should upgrade to this updated package,
which contains a patch to resolve these issues." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the kdegraphics package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdegraphics-3.5.0-0.2.fc4", prefix:"kdegraphics-", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"kdegraphics-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-3193", value:TRUE);
}
