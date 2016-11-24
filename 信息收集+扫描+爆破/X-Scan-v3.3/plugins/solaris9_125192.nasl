#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(36484);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 5.9 (sparc) : 125192-04");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125192-04");
 script_set_attribute(attribute: "description", value:
'Sun Management Centre 3.6.1 PRM: Patch for Solaris 9.
Date this patch was last updated by Sun : Feb/27/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125192-04-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 125192-04");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125192-04", obsoleted_by:"", package:"SUNWesdrg", version:"3.6.1,REV=2.9.2006.04.26");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"125192-04", obsoleted_by:"", package:"SUNWessrg", version:"3.6.1,REV=2.7.2003.09.10");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
