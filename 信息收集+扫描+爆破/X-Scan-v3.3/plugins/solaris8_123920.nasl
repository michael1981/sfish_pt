#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(37363);
 script_version("$Revision: 1.2 $");

 script_name(english: "Solaris 5.8 (sparc) : 123920-11");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 123920-11");
 script_set_attribute(attribute: "description", value:
'Sun Management Center 3.6.1: Patch for Solaris 8.
Date this patch was last updated by Sun : Jun/24/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-123920-11-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 123920-11");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesagt", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesamn", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesclb", version:"3.6.1,REV=2.8.2006.04.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWescli", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesclt", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWescom", version:"3.6.1,REV=2.8.2006.04.27");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWescon", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesdb", version:"3.6.1,REV=2.8.2006.04.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesken", version:"3.6.1,REV=2.8.2006.04.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWesmod", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWespro", version:"3.6.1,REV=2.8.2006.04.13");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWessmn", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWessrv", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWsuagt", version:"3.6.1,REV=2.7.2003.08.28");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"123920-11", obsoleted_by:"", package:"SUNWsusrv", version:"3.6.1,REV=2.7.2003.08.28");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
