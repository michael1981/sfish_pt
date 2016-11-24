#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(38855);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 10 (x86) : 121119-16");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 121119-16");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: Sun Update Connection System Client 1.0.10.
Date this patch was last updated by Sun : May/20/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-121119-16-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 121119-16");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121119-16", obsoleted_by:"", package:"SUNWcsmauth", version:"0.1,REV=2005.05.12.11.43");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121119-16", obsoleted_by:"", package:"SUNWppro-plugin-sunos-base", version:"5.0,REV=2005.01.09.21.19");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121119-16", obsoleted_by:"", package:"SUNWppror", version:"5.0,REV=2005.01.09.21.19");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121119-16", obsoleted_by:"", package:"SUNWpprou", version:"5.0,REV=2005.01.09.21.19");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121119-16", obsoleted_by:"", package:"SUNWupdatemgrr", version:"0.1,REV=2005.05.20.11.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121119-16", obsoleted_by:"", package:"SUNWupdatemgru", version:"0.1,REV=2005.05.20.11.37");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
