#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13674);
 script_bugtraq_id(9641);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0078");
 
 name["english"] = "Fedora Core 1 2004-061: mutt";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-061 (mutt).

Mutt is a text-mode mail user agent. Mutt supports color, threading,
arbitrary key remapping, and a lot of customization.

You should install mutt if you have used it in the past and you prefer
it, or if you are new to mail programs and have not decided which one
you are going to use.

Update Information:

This package fixes CVE-2004-0078, where a specifc message could cause
mutt to crash. This is the vulnerability fixed in the recently released
mutt-1.4.2." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-061.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.4.1-5", prefix:"mutt-", release:"FC1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"mutt-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0078", value:TRUE);
}
