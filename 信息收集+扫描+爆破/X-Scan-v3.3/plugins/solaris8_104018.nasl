#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(23298);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(4089);
 name["english"] = "Solaris 8 (sparc) : 104018-11";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 104018-11
(Solstice Site/SunNet/Domain Manager 2.3 Rev B: jumbo patch).

Date this patch was last updated by Sun : Thu Jul 22 03:32:11 MDT 2004

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-104018-11-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 104018-11"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWcccfg", version:"1.2");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWccrcv", version:"1.2");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWccsnd", version:"1.2");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWsnmag", version:"2.3");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWsnmct", version:"2.3");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"104018-11", obsoleted_by:"", package:"SUNWsnmpd", version:"2.3");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
else 
{
	set_kb_item(name:"BID-4089", value:TRUE);
}
