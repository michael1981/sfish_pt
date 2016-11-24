#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15976);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0422");
 
 name["english"] = "Fedora Core 2 2004-546: flim";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-546 (flim).

FLIM is a library to provide basic features about message
representation and encoding for Emacs.

Update Information:

Update to 1.14.7 release, which also fixes CVE-2004-0422." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/blog/index.php?p=197" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the flim package";
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
if ( rpm_check( reference:"flim-1.14.7-   Release : 0.FC2", prefix:"flim-", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"flim-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0422", value:TRUE);
}
