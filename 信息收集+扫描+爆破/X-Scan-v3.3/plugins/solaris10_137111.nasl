#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(33206);
 script_version("$Revision: 1.16 $");

 script_name(english: "Solaris 10 (sparc) : 137111-08");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 137111-08");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Oct/08/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-137111-08-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 137111-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"FJSVfmd", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcart200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWkvm", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWkvm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWkvmt200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"137111-08", obsoleted_by:"137137-09 ", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
