#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19622);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Fedora Core 3 2005-182: firefox";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-182 (firefox).

Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

This update fixes several security vulnerabilities in Firefox 1.0.
It is recommended that all users update to Firefox 1.0.1.

Additionally, this update backports several fixes from rawhide.
This update enables pango font rendering by default.
This update enables smooth scrolling by default. On slower machines,
this may cause scrolling to lag. If this is the case for you, you may
disable smooth scrolling by going to Edit>Preferences>Advanced and
uncheck 'Use smooth scrolling'.
This update also fixes the issue with downloads going to the user's
home directory instead of the desktop, as expected.
See full changelog below for more." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the firefox package";
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
if ( rpm_check( reference:"firefox-1.0.1-1.3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-debuginfo-1.0.1-1.3.1", release:"FC3") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
