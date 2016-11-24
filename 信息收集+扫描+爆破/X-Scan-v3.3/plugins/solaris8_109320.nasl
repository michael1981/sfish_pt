#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13319);
 script_version("$Revision: 1.30 $");

 script_name(english: "Solaris 8 (sparc) : 109320-23");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 109320-23");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8: lp patch.
Date this patch was last updated by Sun : Aug/21/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-109320-23-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 109320-23");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109320-23", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109320-23", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109320-23", obsoleted_by:"", package:"SUNWppm", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109320-23", obsoleted_by:"", package:"SUNWpsf", version:"13.1,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109320-23", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109320-23", obsoleted_by:"", package:"SUNWscplp", version:"13.1,REV=2000.01.08.18.12");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
