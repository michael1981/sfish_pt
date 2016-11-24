#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(35211);
 script_version("$Revision: 1.5 $");

 script_name(english: "Solaris 10 (x86) : 138889-08");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 138889-08");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: Kernel Patch.
Date this patch was last updated by Sun : Apr/01/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-138889-08-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 138889-08");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWibsdpib", version:"11.10.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.20.40");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.21");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWroute", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138889-08", obsoleted_by:"139556-08 ", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
