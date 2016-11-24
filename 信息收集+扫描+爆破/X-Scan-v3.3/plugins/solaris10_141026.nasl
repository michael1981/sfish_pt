#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(42137);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 10 (sparc) : 141026-06");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141026-06");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: print patch.
Date this patch was last updated by Sun : Oct/13/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-141026-06-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 141026-06");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWippcore", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWpsm-ipp", version:"11.10.0.0,REV=2008.02.29.16.01");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141026-06", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
