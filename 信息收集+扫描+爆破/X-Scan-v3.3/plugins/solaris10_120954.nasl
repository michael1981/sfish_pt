#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(36756);
 script_version("$Revision: 1.2 $");

 script_name(english: "Solaris 5.10 (sparc) : 120954-10");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120954-10");
 script_set_attribute(attribute: "description", value:
'AM 7.0: Sun Java System Access Manager 2005Q4.
Date this patch was last updated by Sun : Aug/03/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120954-10-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 120954-10");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamclnt", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamcon", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamconsdk", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamdistauth", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamfcd", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWampwd", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamrsa", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamsam", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamsdk", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamsdkconfig", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamsfodb", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamsvc", version:"7.0,REV=05.08.10.09.17");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamsvcconfig", version:"7.0,REV=05.08.10.09.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120954-10", obsoleted_by:"", package:"SUNWamutl", version:"7.0,REV=05.08.10.09.17");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
