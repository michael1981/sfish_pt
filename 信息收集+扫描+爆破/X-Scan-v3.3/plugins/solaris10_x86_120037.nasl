#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(24384);
 script_version("$Revision: 1.13 $");

 script_name(english: "Solaris 10 (x86) : 120037-22");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120037-22");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: libc nss ldap PAM zfs patc.
Date this patch was last updated by Sun : Jul/17/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120037-22-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 120037-22");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWaudit", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWdmgtu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWperl584usr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWsra", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWtecla", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWvolu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120037-22", obsoleted_by:"120012-14 ", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
