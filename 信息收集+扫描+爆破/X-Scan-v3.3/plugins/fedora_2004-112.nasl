#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13693);
 script_bugtraq_id(10242);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-1023", "CVE-2004-0226", "CVE-2004-0232");
 
 name["english"] = "Fedora Core 1 2004-112: mc";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-112 (mc).

Midnight Commander is a visual shell much like a file manager, only
with many more features. It is a text mode application, but it also
includes mouse support if you are running GPM. Midnight Commander's
best features are its ability to FTP, view tar and zip files, and to
poke into RPMs for specific files.

Update Information:

Several buffer overflows, several temporary file creation
vulnerabilities, and one format string vulnerability have been
discovered in Midnight Commander.  These vulnerabilities were
discovered mostly by Andrew V. Samoilov and Pavel Roskin.  The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the names CVE-2004-0226, CVE-2004-0231, and CVE-2004-0232 to these
issues." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-112.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the mc package";
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
if ( rpm_check( reference:"mc-4.6.0-14.10", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mc-debuginfo-4.6.0-14.10", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"mc-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-1023", value:TRUE);
 set_kb_item(name:"CVE-2004-0226", value:TRUE);
 set_kb_item(name:"CVE-2004-0232", value:TRUE);
}
