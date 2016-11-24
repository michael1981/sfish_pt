#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23321);
 script_version("$Revision: 1.7 $");

 script_name(english: "Solaris 5.8 (sparc) : 110046-02");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 110046-02");
 script_set_attribute(attribute: "description", value:
'SunVTS4.0 UI patch.
Date this patch was last updated by Sun : Sep/12/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-110046-02-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 110046-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110046-02", obsoleted_by:"", package:"SUNWodu", version:"4.0,REV=38.99.12.09");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110046-02", obsoleted_by:"", package:"SUNWvts", version:"4.0,REV=38.99.12.09");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
