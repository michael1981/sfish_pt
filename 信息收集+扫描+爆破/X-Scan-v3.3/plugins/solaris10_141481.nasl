#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(40586);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 5.10 (sparc) : 141481-02");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141481-02");
 script_set_attribute(attribute: "description", value:
'Sun Virtual Desktop Infrastructure Software version 3.0 Patch Upda.
Date this patch was last updated by Sun : Aug/12/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-141481-02-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 141481-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWrdpb", version:"1.0_9");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-admin-libs-fr", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-admin-libs-ja", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-admin-libs-sv", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-admin-libs-zh", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-admin", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-client", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-kiosk", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-migrate", version:"3.0_71,REV=2009.03.11.11.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"141481-02", obsoleted_by:"", package:"SUNWvda-service", version:"3.0_71,REV=2009.03.11.11.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
