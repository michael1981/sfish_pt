#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14704);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0817");
 
 name["english"] = "Fedora Core 2 2004-301: imlib";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-301 (imlib).

Imlib is a display depth independent image loading and rendering
library. Imlib is designed to simplify and speed up the process of
loading images and obtaining X Window System drawables. Imlib
provides many simple manipulation routines which can be used for
common operations.

Install imlib if you need an image loading and rendering library for
X11R6, or if you are installing GNOME. You may also want to install
the imlib-cfgeditor package, which will help you configure Imlib.

Update Information:

Several heap overflow vulnerabilities have been found in the imlib BMP
image handler. An attacker could create a carefully crafted BMP file in
such a way that it would cause an application linked with imlib to
execute
arbitrary code when the file was opened by a victim. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name
CVE-2004-0817 to this issue.

Users of imlib should update to this updated package which contains
backported patches and is not vulnerable to these issues." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-301.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the imlib package";
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
if ( rpm_check( reference:"imlib-1.9.13-19", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-19", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-19", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib-debuginfo-1.9.13-19", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"imlib-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0817", value:TRUE);
}
