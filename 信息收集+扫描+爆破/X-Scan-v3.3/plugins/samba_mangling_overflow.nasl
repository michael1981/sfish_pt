#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(13657);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2004-0686");
 script_bugtraq_id(10781);
 script_xref(name:"OSVDB", value:"8191");

 script_name(english:"Samba Mangling Method Hash Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It might be possible to run arbitrary code on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable 
to a buffer overflow if the option 'mangling method' is set to 'hash' 
in smb.conf (which is not the case by default).

An attacker may exploit this flaw to execute arbitrary commands on the 
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-2.2.10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.0.5.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.2.10 or 3.0.5" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 script_summary(english:"checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 if ( !defined_func("bn_random"))
 	script_dependencie("smb_nativelanman.nasl");
 else
	script_dependencie("smb_nativelanman.nasl", "freebsd_samba_304_4.nasl", "redhat-RHSA-2004-259.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0686") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.[0-9]$", string:lanman))
  security_warning(139);
 else if(ereg(pattern:"Samba 3\.0\.[0-4]$", string:lanman))
  security_warning(139);
}
