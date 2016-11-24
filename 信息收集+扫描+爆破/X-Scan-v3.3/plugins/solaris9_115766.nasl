#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23511);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 5.9 (sparc) : 115766-15");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 115766-15");
 script_set_attribute(attribute: "description", value:
'AM 6.2: Sun Java System Access Manager.
Date this patch was last updated by Sun : Feb/05/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-115766-15-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 115766-15");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamcon", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamconsdk", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamfcd", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamjwsdp", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWampwd", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamsam", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamsci", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamsdk", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamsdkconfig", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamsvc", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamsvcconfig", version:"6.2,REV=04.04.23.20.25");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"115766-15", obsoleted_by:"", package:"SUNWamutl", version:"6.2,REV=04.04.23.20.24");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
