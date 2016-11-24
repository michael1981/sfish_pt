#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(12014);
 script_version("$Revision: 1.6 $");

 name["english"] = 

 script_name(english:"Free Community Detection");
 script_summary(english:"Free Community detection");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"An adware program is installed on the remote Windows host."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "Free Community is installed on the remote host.  This is an adware\n",
     "program that monitors web traffic, and replaces banner advertisements\n",
     "with advertisements of its choosing."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.ca.com/us/securityadvisor/pest/pest.aspx?id=453078027"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this program using a spyware or adware removal product."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}


# start the script
include("smb_func.inc");
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);


path[0] = "software\classes\clsid\{2e9caff6-30c7-4208-8807-e79d4ec6f806}";
path[1] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{2e9caff6-30c7-4208-8807-e79d4ec6f806}";



port = kb_smb_transport();
if(!port || ! get_port_state(port) )exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

          
soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) ) 
       { 
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_warning(kb_smb_transport()); 
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
