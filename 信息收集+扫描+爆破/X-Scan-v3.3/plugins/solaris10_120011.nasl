#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(26157);
 script_version("$Revision: 1.11 $");

 script_name(english: "Solaris 10 (sparc) : 120011-14");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120011-14");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Sep/12/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120011-14-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 120011-14");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"FJSVcpcu", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"FJSVpiclu", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWatfsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWauda", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWaudh", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWaudit", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWbart", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWbcp", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcart200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcnetr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.07.25.02.27");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWcti2", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdcsr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdfbh", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdhcm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdhcsu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdmgtu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdoc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdrcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdrr", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdrr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdscpr", version:"11.10.0,REV=2006.07.29.05.17");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWefcl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWefcr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWerid", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWfruip", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWftduu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWidn", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.09.15.00.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.21.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWipfr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWippcore", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWipplr", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWipplu", version:"13.1,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWixgb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkey", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.01.20.17.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWkvmt200", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWlibsasl", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWlldap", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWncar", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWntpu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWopenssl-include", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpcmci", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWperl584usr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpl5u", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpool", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpoolr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpppdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.05.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWqos", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWrcapr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWrcapu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWrge", version:"11.10.0,REV=2006.04.06.02.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWroute", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsadmi", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsckmr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWses", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWslpu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsndmr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsra", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWtecla", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWudapltr", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWuksp", version:"11.10.0,REV=2006.04.06.02.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWuprl", version:"11.10.0,REV=2006.04.06.02.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWus", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWusbu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWvolu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWwbsup", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWwrsm", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWxge", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWypu", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWzoner", version:"11.10.0,REV=2005.01.21.15.53");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
