#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(19370);
 script_version("$Revision: 1.27 $");

 script_name(english: "Solaris 10 (x86) : 118844-30");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 118844-30");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: kernel Patch.
Date this patch was last updated by Sun : Mar/02/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-118844-30-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 118844-30");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"CADP160", version:"1.21,REV=2005.01.17.23.31");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNW1394", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWadp", version:"11.10.0,REV=2005.01.17.23.31");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcadp", version:"11.10.0,REV=2005.01.17.23.31");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcnetr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWdfbh", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWipfr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWkey", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWkvm", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWmddr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWopenssl-commands", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWpcmci", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWpsdcr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWpsdir", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWpsh", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWqos", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWradpu320", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWrcapu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWrmodr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWrmodu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWrmwbu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWsndmr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWtnfc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-30", obsoleted_by:"118855-36 ", package:"SUNWxge", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
