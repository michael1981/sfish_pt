#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(24848);
 script_version("$Revision: 1.4 $");

 script_name(english: "Solaris 5.10 (x86) : 119044-03");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119044-03");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8 5.9 5.10 5.8_x86 5.9_x86 5.10_x86: JDMK 5.1 patch.
Date this patch was last updated by Sun : Mar/02/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-119044-03-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 119044-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119044-03", obsoleted_by:"", package:"SUNWjdmk-runtime-jmx", version:"5.1,REV=34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119044-03", obsoleted_by:"", package:"SUNWjdmk-runtime", version:"5.1,REV=34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119044-03", obsoleted_by:"", package:"SUNWjdmk-sdk", version:"5.1,REV=34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
