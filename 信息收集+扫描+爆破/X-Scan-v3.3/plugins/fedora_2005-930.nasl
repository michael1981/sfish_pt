#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19875);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Fedora Core 4 2005-930: yelp";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-930 (yelp).

Yelp is the Gnome 2 help/documentation browser. It is designed
to help you browse all the documentation on your system in
one central tool.

Update Information:

There were several security flaws found in the mozilla
package, which yelp depends on.   Users of yelp are advised
to upgrade to this updated package which has been rebuilt
against a version of mozilla not vulnerable to these flaws." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the yelp package";
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
if ( rpm_check( reference:"yelp-2.10.0-1.4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
