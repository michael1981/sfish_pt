#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");


if(description)
{
 script_id(11635);
 script_cve_id("CVE-2003-1572");
 script_bugtraq_id(7612);
 script_xref(name:"OSVDB", value:"2213");
 script_xref(name:"Secunia", value:"8792");
 script_version("$Revision: 1.4 $");

 script_name(english:"Sun Java Media Framework (JMF) Code Execution Vulnerability");
 script_summary(english:"Determines the presence of JMF");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A framework installed on the remote Windows host has a code execution\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using Sun Microsystems's Java Media Framework\n",
     "(JMF).\n\n",
     "There is a bug in the version installed which may allow an untrusted\n",
     "applet to crash the Java Virtual Machine it is being run on, or even\n",
     "to gain unauthorized privileges.\n\n",
     "An attacker could exploit this flaw to execute arbitrary code on\n",
     "this host. To exploit this flaw, the attacker would need to trick\n",
     "a user into running a malicious Java applet."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-06/0200.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-201308-1"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to JMF 2.1.1e or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


include("smb_func.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:kb_smb_name());

r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Sun Microsystems, Inc.\JMF", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"LatestVersion");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

if ( isnull(item) ) exit(1);
if(ereg(pattern:"^([0-1]\.|2\.0|2\.1\.0|2\.1\.1($|[a-d]))$", string:item[1]))security_hole(port);
