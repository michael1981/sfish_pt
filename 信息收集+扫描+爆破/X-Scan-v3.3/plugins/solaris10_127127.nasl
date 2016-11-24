#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(32164);
 script_version("$Revision: 1.5 $");

 script_name(english: "Solaris 10 (sparc) : 127127-11");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 127127-11");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Apr/25/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-127127-11-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 127127-11");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"FJSVcpcu", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"FJSVfmd", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"FJSVpiclu", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNW1394", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWatfsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWaudit", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcakrnt2000", version:"11.10.0,REV=2006.08.08.12.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcart200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.07.25.02.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcstl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWcti2", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.33");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWdrr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWdrr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWfruid", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWfruip", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWftduu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWgss", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWgssdh", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWgssk", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWidn", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.09.15.00.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWippcore", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWipplr", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWipplu", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkrbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWkvmt200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWluxl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWn2cp", version:"11.10.0,REV=2007.07.08.21.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWniumx", version:"11.10.0,REV=2007.06.20.13.33");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpamsc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpcr", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpiclr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpl5u", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpsr", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWrcmds", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.33");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWscplp", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWspnego", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtnetc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtnetd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtsg", version:"11.10.0,REV=2006.10.13.16.23");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtsr", version:"11.10.0,REV=2006.10.13.16.23");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWtsu", version:"11.10.0,REV=2006.09.28.16.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWudapltr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWus", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWvolu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWwbsup", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWwrsm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWypr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWypu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"127127-11", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
