#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(42142);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 10 (x86) : 141445-09");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141445-09");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: kernel patch.
Date this patch was last updated by Sun : Oct/13/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-141445-09-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 141445-09");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWahci", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWatfsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWauda", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWdoc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWfmdr", version:"11.10.0,REV=2006.03.29.01.57");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWgrub", version:"11.10.0,REV=2005.09.03.12.22");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWgrubS", version:"11.10.0,REV=2005.09.14.10.55");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWibsdpib", version:"11.10.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWibsdpu", version:"11.10.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWigb", version:"11.10.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWio-tools", version:"11.10.0,REV=2009.06.25.23.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWipoib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWippcore", version:"13.1,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWiscsitgtu", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWixgbe", version:"11.10.0,REV=2008.08.11.22.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWlxu", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWmv88sx", version:"11.10.0,REV=2006.03.27.18.17");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnv-sata", version:"11.10.1,REV=2008.08.11.22.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.21");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpcmem", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpiclr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpmr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpool", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsdcr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsdir", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsdpr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsh", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsm-ipp", version:"11.10.0.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.01.09");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.12");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWrpcib", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWsadmi", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWudapltr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWudaplu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWvolu", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWxvmpv", version:"11.10.0,REV=2008.02.29.14.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141445-09", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
