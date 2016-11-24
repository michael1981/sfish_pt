#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(25395);
 script_version("$Revision: 1.30 $");

 script_name(english: "Solaris 10 (x86) : 125720-32");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125720-32");
 script_set_attribute(attribute: "description", value:
'X11 6.8.0_x86: Xorg server patch.
Date this patch was last updated by Sun : Jun/19/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125720-32-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 125720-32");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-cfg", version:"6.8.2.5.10.0110,REV=0.2005.06.29");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-client-docs", version:"6.8.2.5.10.0110,REV=0.2005.06.21");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-client-programs", version:"6.8.2.5.10.0110,REV=0.2005.06.21");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-devel-docs", version:"6.8.2.5.10.0110,REV=0.2005.06.21");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-doc", version:"6.8.0.5.10.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-graphics-ddx", version:"6.8.0.5.10.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-mesa", version:"6.8.2.5.10.0113,REV=0.2005.08.02");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-server", version:"6.8.0.5.10.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxorg-xkb", version:"6.8.0.5.10.7400,REV=0.2004.12.15");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125720-32", obsoleted_by:"", package:"SUNWxvnc", version:"6.6.2.0500,REV=0.2008.02.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
