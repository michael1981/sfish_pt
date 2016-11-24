#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13440);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 8 (x86) : 109923-05");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 109923-05");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8_x86: pcelx and pcser driver patch.
Date this patch was last updated by Sun : Dec/03/03');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-109923-05-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 109923-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109923-05", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109923-05", obsoleted_by:"", package:"SUNWpcelx", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109923-05", obsoleted_by:"", package:"SUNWpcmci", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109923-05", obsoleted_by:"", package:"SUNWpcser", version:"11.8.0,REV=2000.01.08.18.17");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
