#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11304);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2002-0186", "CVE-2002-0187");
 script_bugtraq_id(5004, 5005);
 script_xref(name:"OSVDB", value:"5343");
 script_xref(name:"OSVDB", value:"5347");
 script_xref(name:"IAVA", value:"2002-B-0004");
 
 script_name(english:"MS02-030: Unchecked Buffer in SQLXML (321911)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through SQL server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SQLXML.  There are flaws in this
application that may allow a remote attacker to execute arbitrary code
on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-030.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for SQLXML");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "mssql_version.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

version = get_kb_item("mssql/SQLVersion");
if(!version)exit(0);

# SP3 applied - don't know the version number yet
#if(ereg(pattern:"[8-9]\.00\.([8-9][0-9][0-9]|7[67][0-9])", string:version))exit(0);

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);


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


key = "SYSTEM\CurrentControlSet\Services\SQLXML\Performance";
item = "Library";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  # If it's SQL Server Gold, then issue an alert.
  if(ereg(pattern:"^8\..*", string:version)) 
  {  
   key = "SOFTWARE\Microsoft\Updates\DataAccess\Q321858";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( isnull(key_h2) )
 {
 set_kb_item(name:"SMB/Missing/MS02-030", value:TRUE);
 security_warning(port);
 }
   else
     RegCloseKey (handle:key_h2);
  }

  # SQLXML 2.0
  else if(ereg(pattern:".*sqlxml2\.dll", string:value))
  {
   key = "SOFTWARE\Microsoft\Updates\SQLXML 2.0\Q321460";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( isnull(key_h2) )
 {
 set_kb_item(name:"SMB/Missing/MS02-030", value:TRUE);
 security_warning(port);
 }
   else
     RegCloseKey (handle:key_h2);
  }

  # SQLXML 3.0
  else if(ereg(pattern:".*sqlxml3\.dll", string:value))
  {
   key = "SOFTWARE\Microsoft\Updates\SQLXML 3.0\Q320833";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( isnull(key_h2) )
 {
 set_kb_item(name:"SMB/Missing/MS02-030", value:TRUE);
 security_warning(port);
 }
   else
     RegCloseKey (handle:key_h2);
  }
 }

 RegCloseKey (handle:key_h);
}


RegCloseKey (handle:hklm);
NetUseDel ();
