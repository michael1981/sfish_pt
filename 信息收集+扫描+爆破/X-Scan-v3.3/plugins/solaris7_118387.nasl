#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23263);
 script_version("$Revision: 1.4 $");

 script_name(english: "Solaris 5.7 (sparc) : 118387-09");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 118387-09");
 script_set_attribute(attribute: "description", value:
'Sun Management Centre 3.5.1: Patch for Solaris 7.
Date this patch was last updated by Sun : Nov/20/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-118387-09-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 118387-09");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWenesf", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWenesi", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWesagt", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWesamn", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWescom", version:"3.5,REV=2.7.2004.05.04");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWescon", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWesdb", version:"3.5,REV=2.7.2006.09.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWesgui", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWesken", version:"3.5,REV=2.7.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWespro", version:"3.5,REV=2.7.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWessa", version:"3.5,REV=2.7.2006.09.05");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWessrv", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWessvc", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWsuagt", version:"3.5,REV=2.6.2004.04.15");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"118387-09", obsoleted_by:"", package:"SUNWsusrv", version:"3.5,REV=2.6.2004.04.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
