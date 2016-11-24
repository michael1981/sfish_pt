#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(20229);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 
 name["english"] = "Fedora Core 4 2005-1085: gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-1085 (gdk-pixbuf).

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment. The GdkPixBuf library provides image
loading facilities, the rendering of a GdkPixBuf into various formats
(drawables or GdkRGB buffers), and a cache interface.

Update Information:

The gdk-pixbuf package contains an image loading library
used with the GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes XPM images.
An attacker could create a carefully crafted XPM file in
such a way that it could cause an application linked with
gdk-pixbuf to execute arbitrary code when the file was
opened by a victim. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-3186 to this issue.

Ludwig Nussel discovered an integer overflow bug in the way
gdk-pixbuf processes XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause
an application linked with gdk-pixbuf to execute arbitrary
code or crash when the file was opened by a victim. The
Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-2976 to this issue.

Ludwig Nussel also discovered an infinite-loop denial of
service bug in the way gdk-pixbuf processes XPM images. An
attacker could create a carefully crafted XPM file in such a
way that it could cause an application linked with
gdk-pixbuf to stop responding when the file was opened by a
victim. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2975 to this issue.

Users of gdk-pixbuf are advised to upgrade to these updated
packages, which contain backported patches and are not
vulnerable to these issues." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the gdk-pixbuf package";
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
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-18.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"gdk-pixbuf-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
