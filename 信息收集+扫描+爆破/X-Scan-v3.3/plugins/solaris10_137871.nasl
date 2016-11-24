#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(32365);
 script_version("$Revision: 1.4 $");

 script_name(english: "Solaris 10 (sparc) : 137871-02");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 137871-02");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: tk patch.
Date this patch was last updated by Sun : Aug/11/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-137871-02-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 137871-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137871-02", obsoleted_by:"", package:"SUNWTk", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137871-02", obsoleted_by:"", package:"SUNWTkS", version:"11.10.0,REV=2005.01.08.05.16");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
