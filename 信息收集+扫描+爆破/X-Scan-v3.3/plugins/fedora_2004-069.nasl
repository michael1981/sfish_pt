#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13677);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106");
 
 name["english"] = "Fedora Core 1 2004-069: XFree86";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-069 (XFree86).

XFree86 is an open source implementation of the X Window System.  It
provides the basic low level functionality which full fledged
graphical user interfaces (GUIs) such as GNOME and KDE are designed
upon.

Update Information:

Updated XFree86 packages that fix a privilege escalation vulnerability are
now available.

XFree86 is an implementation of the X Window System, providing the core
graphical user interface and video drivers.

iDefense discovered two buffer overflows in the parsing of the 'font.alias'
file. A local attacker could exploit this vulnerability by creating a
carefully-crafted file and gaining root privileges.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2004-0083 and CVE-2004-0084 to these issues.

Additionally David Dawes discovered additional flaws in reading font files.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0106 to these issues.

All users of XFree86 are advised to upgrade to these erratum packages,
which contain a backported fix and are not vulnerable to these issues.

Red Hat would like to thank David Dawes from XFree86 for the patches and
notification of these issues." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-069.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the XFree86 package";
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
if ( rpm_check( reference:"XFree86-4.3.0-55", prefix:"XFree86-", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"XFree86-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0083", value:TRUE);
 set_kb_item(name:"CVE-2004-0084", value:TRUE);
 set_kb_item(name:"CVE-2004-0106", value:TRUE);
}
