#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13423);
 script_version("$Revision: 1.25 $");

 script_name(english: "Solaris 8 (x86) : 109148-42");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 109148-42");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8_x86: linker patch.
Date this patch was last updated by Sun : Sep/17/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-109148-42-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 109148-42");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWbtool", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWosdem", version:"11.8.0,REV=2000.01.08.18.17");
e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"109148-42", obsoleted_by:"", package:"SUNWtoo", version:"11.8.0,REV=2000.01.08.18.17");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
