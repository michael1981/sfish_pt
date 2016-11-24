#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(26985);
 script_version("$Revision: 1.14 $");

 script_name(english: "Solaris 5.10 (sparc) : 125137-17");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125137-17");
 script_set_attribute(attribute: "description", value:
'JavaSE 6: update 16 patch (equivalent to JDK 6u16), 64bit.
Date this patch was last updated by Sun : Aug/14/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125137-17-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 125137-17");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"125137-17", obsoleted_by:"", package:"SUNWj6dmx", version:"1.6.0,REV=2006.11.29.04.58");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"125137-17", obsoleted_by:"", package:"SUNWj6dvx", version:"1.6.0,REV=2006.11.29.04.58");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"125137-17", obsoleted_by:"", package:"SUNWj6rtx", version:"1.6.0,REV=2006.11.29.04.58");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
