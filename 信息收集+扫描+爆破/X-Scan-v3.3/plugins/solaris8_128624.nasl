#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(29828);
 script_version("$Revision: 1.17 $");

 script_name(english: "Solaris 8 (sparc) : 128624-12");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 128624-12");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8: LDAP2 client, libc, libthread and libnsl libraries patc.
Date this patch was last updated by Sun : Apr/27/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-128624-12-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 128624-12");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWapppr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWapppu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWarcx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWatfsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWatfsu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcarx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcarx", version:"11.8.0,REV=2000.01.13.13.40");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcslx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcstl", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcstlx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWcsxu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWdpl", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWdplx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWlldap", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWmdbx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWnisr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWnisu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWpppd", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWpppdr", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWpppdu", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWpppdx", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"128624-12", obsoleted_by:"", package:"SUNWpppgS", version:"11.8.0,REV=2001.02.21.14.02");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
