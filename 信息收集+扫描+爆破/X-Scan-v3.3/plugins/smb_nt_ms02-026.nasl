#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11306);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2002-0369");
 script_bugtraq_id(4958);
 script_xref(name:"OSVDB", value:"5314");
 
 script_name(english:"MS02-026: ASP.NET Worker Process StateServer Mode Remote Overflow (322289)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote ASP.NET installation might be vulnerable to a buffer
overflow when an application enables StateServer mode. 

An attacker may use it to cause a denial of service or run arbitrary
code with the same privileges as the process being exploited
(typically an unprivileged account)." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for ASP.NET :

http://www.microsoft.com/technet/security/bulletin/ms02-026.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for MS Hotfix Q322289");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "smb_reg_service_pack_W2K.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

version = get_kb_item("SMB/WindowsVersion");
if(ereg(pattern:"([6-9]\.[0-9])|(5\.[2-9])", string:version))exit(0);


name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}


key = "SOFTWARE\Microsoft\.NetFramework";
item  = "InstallRoot";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  key = "SOFTWARE\Microsoft\Updates\.NetFramework\1.0\S321884";
  item = "Description";

  key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h2) )
  {
   value = RegQueryValue(handle:key_h2, item:item);
   if (isnull (value) || !ereg(pattern:"Service Pack [2-9]", string:value[1]))
   {
    key = "SOFTWARE\Microsoft\Updates\.NetFramework\1.0\NDP10SP317396\M322289";

    key_h3 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( isnull(key_h3) )
 {
 set_kb_item(name:"SMB/Missing/MS02-026", value:TRUE);
 security_warning(port);
 }
    else
      RegCloseKey (handle:key_h3);
   }

   RegCloseKey(handle:key_h2);
  }

 }

 RegCloseKey (handle:key_h);
}


RegCloseKey (handle:hklm);
NetUseDel ();
