#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(23588);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Solaris 9 (i386) : 116578-42";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 116578-42
(Calendar Server SunOS 5.8_x86 5.9_x86 5.10_x86: Core patch).

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-116578-42-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 116578-42"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116578-42", obsoleted_by:"121658-17", package:"SUNWica5", version:"6.0,REV=2003.11.14.17.38.10");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116578-42", obsoleted_by:"121658-17", package:"SUNWics5", version:"6.0,REV=2003.11.14.17.38.10");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
