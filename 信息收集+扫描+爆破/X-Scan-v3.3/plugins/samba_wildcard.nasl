#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15705);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2004-0882", "CVE-2004-0930");
 script_bugtraq_id(11624, 11678);
 script_xref(name:"OSVDB", value:"11555");
 script_xref(name:"OSVDB", value:"11782");

 script_name(english: "Samba Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is affected
by a remote denial of service vulnerability as well as a buffer
overflow. 

The Wild Card DoS vulnerability may allow an attacker to make the
remote server consume excessive CPU cycles. 

The QFILEPATHINFO Remote buffer overflow vulnerability may allow an
attacker to execute code on the server. 

An attacker needs a valid account or enough credentials to exploit
those flaws." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2004-0882.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2004-0930.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 if ( !defined_func("bn_random"))
 	script_dependencie("smb_nativelanman.nasl");
 else
	script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0930") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.[0-7]$", string:lanman))security_hole(139);
}
