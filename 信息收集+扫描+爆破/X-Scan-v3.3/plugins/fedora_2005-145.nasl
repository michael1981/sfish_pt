#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16466);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-0100");
 
 name["english"] = "Fedora Core 2 2005-145: xemacs";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-145 (xemacs).

XEmacs is a highly customizable open source text editor and
application development system. It is protected under the
GNU Public License and related to other versions of Emacs,
in particular GNU Emacs. Its emphasis is on modern graphical
user interface support and an open software development
model, similar to Linux.

This package contains xemacs built for X Windows with MULE support.

Update Information:

Update to 21.4.17 stable release, which also fixes the
CVE-2005-0100 movemail string format vulnerability." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=398" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the xemacs package";
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
if ( rpm_check( reference:"xemacs-21.4.17-0.FC2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-common-21.4.17-0.FC2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-nox-21.4.17-0.FC2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-el-21.4.17-0.FC2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-info-21.4.17-0.FC2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-debuginfo-21.4.17-0.FC2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"xemacs-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0100", value:TRUE);
}
