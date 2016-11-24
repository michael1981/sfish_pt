#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(27015);
 script_version("$Revision: 1.15 $");

 script_name(english: "Solaris 5.8 (x86) : 125138-17");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125138-17");
 script_set_attribute(attribute: "description", value:
'JavaSE 6_x86: update 16 patch (equivalent to JDK 6u16).
Date this patch was last updated by Sun : Aug/14/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125138-17-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 125138-17");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"125138-17", obsoleted_by:"", package:"SUNWj6cfg", version:"1.6.0,REV=2006.11.29.05.03");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"125138-17", obsoleted_by:"", package:"SUNWj6dev", version:"1.6.0,REV=2006.11.29.05.03");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"125138-17", obsoleted_by:"", package:"SUNWj6dmo", version:"1.6.0,REV=2006.11.29.05.03");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"125138-17", obsoleted_by:"", package:"SUNWj6jmp", version:"1.6.0,REV=2006.12.07.19.34");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"125138-17", obsoleted_by:"", package:"SUNWj6man", version:"1.6.0,REV=2006.12.07.16.42");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"125138-17", obsoleted_by:"", package:"SUNWj6rt", version:"1.6.0,REV=2006.11.29.05.03");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
