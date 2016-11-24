#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:054
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24432);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:054: MozillaFirefox,MozillaThunderbird,seamonkey";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:054 (MozillaFirefox,MozillaThunderbird,seamonkey).


Security updates have been released that bring Mozilla Firefox to
version 1.5.0.7, Mozilla Thunderbird to version 1.5.0.7 and Mozilla
Seamonkey to 1.0.5.

Seamonkey and Thunderbird were released early this week, Firefox was
released today.

Please also see
http://www.mozilla.org/projects/security/known-vulnerabilities.html
for more details." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_54_mozilla.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the MozillaFirefox,MozillaThunderbird,seamonkey package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"MozillaFirefox-1.5.0.7-1.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.7-1.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.7-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.5.0.7-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.7-1.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.7-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.5.0.7-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.7-1.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.7-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
