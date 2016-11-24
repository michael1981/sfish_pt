#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13579);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 9 (x86) : 112662-09");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 112662-09");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9_x86: IIIM and X Input & Output Method patch.
Date this patch was last updated by Sun : Jun/25/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-112662-09-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 112662-09");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"JSatsvw", version:"1.0,REV=2002.11.01.17.06");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWcleu", version:"9.0,REV=2002.08.19.13.15");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWhkleu", version:"9.0,REV=2002.08.19.13.15");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWhleu", version:"9.0,REV=2002.08.19.13.15");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWiiimr", version:"1.1,REV=1.0.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWiiimu", version:"1.1,REV=1.0.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWj3irt", version:"1.1,REV=1.0.55");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWjwncx", version:"1.2,REV=2002.03.07.13.19");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWjxplt", version:"1.5,REV=2002.03.04.19.40");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWlccom", version:"5.8,REV=2002.01.08.10.48");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWxi18n", version:"4.1,REV=1.0.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"112662-09", obsoleted_by:"", package:"SUNWxim", version:"4.1,REV=1.0.59");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
