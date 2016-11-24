#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(28212);
 script_version ("$Revision: 1.9 $");
 if ( NASL_LEVEL >= 3000 )
  script_cve_id("CVE-2007-3456", "CVE-2007-4678", "CVE-2007-2926", "CVE-2005-0953", "CVE-2005-1260", 
                "CVE-2007-4679", "CVE-2007-4680", "CVE-2007-0464", "CVE-2007-4681", "CVE-2007-4682", 
                "CVE-2007-3999", "CVE-2007-4743", "CVE-2007-3749", "CVE-2007-4683", "CVE-2007-4684", 
                "CVE-2007-4685", "CVE-2006-6127", "CVE-2007-4686", "CVE-2007-4687", "CVE-2007-4688", 
                "CVE-2007-4269", "CVE-2007-4689", "CVE-2007-4267", "CVE-2007-4268", "CVE-2007-4690", 
                "CVE-2007-4691", "CVE-2007-0646", "CVE-2007-4692", "CVE-2007-4693", "CVE-2007-4694", 
                "CVE-2007-4695", "CVE-2007-4696", "CVE-2007-4697", "CVE-2007-4698", "CVE-2007-3758", 
                "CVE-2007-3760", "CVE-2007-4671", "CVE-2007-3756", "CVE-2007-4699", "CVE-2007-4700", 
                "CVE-2007-4701");
 script_bugtraq_id(26444);
 script_xref(name:"OSVDB", value:"15237");
 script_xref(name:"OSVDB", value:"16767");
 script_xref(name:"OSVDB", value:"30695");
 script_xref(name:"OSVDB", value:"32704");
 script_xref(name:"OSVDB", value:"32708");
 script_xref(name:"OSVDB", value:"36235");
 script_xref(name:"OSVDB", value:"37324");
 script_xref(name:"OSVDB", value:"37332");
 script_xref(name:"OSVDB", value:"38054");
 script_xref(name:"OSVDB", value:"38529");
 script_xref(name:"OSVDB", value:"38531");
 script_xref(name:"OSVDB", value:"38533");
 script_xref(name:"OSVDB", value:"38535");
 script_xref(name:"OSVDB", value:"40661");
 script_xref(name:"OSVDB", value:"40662");
 script_xref(name:"OSVDB", value:"40663");
 script_xref(name:"OSVDB", value:"40664");
 script_xref(name:"OSVDB", value:"40665");
 script_xref(name:"OSVDB", value:"40666");
 script_xref(name:"OSVDB", value:"40667");
 script_xref(name:"OSVDB", value:"40668");
 script_xref(name:"OSVDB", value:"40669");
 script_xref(name:"OSVDB", value:"40670");
 script_xref(name:"OSVDB", value:"40671");
 script_xref(name:"OSVDB", value:"40672");
 script_xref(name:"OSVDB", value:"40673");
 script_xref(name:"OSVDB", value:"40674");
 script_xref(name:"OSVDB", value:"40675");
 script_xref(name:"OSVDB", value:"40676");
 script_xref(name:"OSVDB", value:"40677");
 script_xref(name:"OSVDB", value:"40678");
 script_xref(name:"OSVDB", value:"40679");
 script_xref(name:"OSVDB", value:"40680");
 script_xref(name:"OSVDB", value:"40681");
 script_xref(name:"OSVDB", value:"40682");
 script_xref(name:"OSVDB", value:"40683");
 script_xref(name:"OSVDB", value:"40684");
 script_xref(name:"OSVDB", value:"40685");
 script_xref(name:"OSVDB", value:"40686");
 script_xref(name:"OSVDB", value:"40687");
 script_xref(name:"OSVDB", value:"40688");

 script_name(english:"Mac OS X < 10.4.11 Multiple Vulnerabilities (Security Update 2007-008)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 which is older
than version 10.4.11 or a version of Mac OS X 10.3 which does not have
Security Update 2007-008 applied. 

This update contains several security fixes for the following programs :

 - Flash Player Plugin
 - AppleRAID
 - BIND
 - bzip2
 - CFFTP
 - CFNetwork
 - CoreFoundation
 - CoreText
 - Kerberos
 - Kernel
 - remote_cmds
 - Networking
 - NFS
 - NSURL
 - Safari
 - SecurityAgent
 - WebCore
 - WebKit" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307041" );
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 : Upgrade to Mac OS X 10.4.11 :

http://www.apple.com/support/downloads/macosx10411updateppc.html
http://www.apple.com/support/downloads/macosx10411updateintel.html

Mac OS X 10.3 : Apply Security Update 2007-008 :

http://www.apple.com/support/downloads/securityupdate20070081039client.html
http://www.apple.com/support/downloads/securityupdate20070081039server.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for the version of Mac OS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) {
	os = get_kb_item("Host/OS");
	confidence = get_kb_item("Host/OS/Confidence");
	if ( confidence <= 90 ) exit(0);
	}
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.([1-9]$|10))", string:os)) security_hole(0);
else if ( ereg(pattern:"Mac OS X 10\.3\.", string:os) )
{
 packages = get_kb_item("Host/MacOSX/packages");
 if ( ! packages ) exit(0);
 if (!egrep(pattern:"^SecUpd(Srvr)?2007-008", string:packages)) security_hole(0);
}
