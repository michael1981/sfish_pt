#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23415);
 script_version("$Revision: 1.15 $");

 script_name(english: "Solaris 5.8 (sparc) : 119465-17");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119465-17");
 script_set_attribute(attribute: "description", value:
'Sun Java(TM) System Access Manager 6 2005Q1.
Date this patch was last updated by Sun : Jun/29/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-119465-17-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 119465-17");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamclnt", version:"6.3,REV=04.12.14.01.46");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamcon", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamconsdk", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamfcd", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWampwd", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamsam", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamsdk", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamsdkconfig", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamsfodb", version:"6.3,REV=04.12.14.01.46");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamsvc", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"119465-17", obsoleted_by:"", package:"SUNWamsvcconfig", version:"6.2,REV=04.04.23.20.25");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
