#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12003);
 
 script_version("$Revision: 1.6 $");

 name["english"] = "TIMESINK detection";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"A spyware appears to be installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the TIMESINK program.  
You should ensure that :

  - the user intended to install TIMESINK (it is sometimes silently installed)
  - the use of TIMESINK matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot." );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/securityadvisor/pest/pest.aspx?id=453059958" );
 script_set_attribute(attribute:"solution", value:
"Uninstall this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "TIMESINK detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}


# start the script

include("smb_func.inc");
if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

path[0] = "software\conducent";
path[1] = "software\microsoft\windows\currentversion\uninstall\flexpak";
path[2] = "software\timesink  inc.";


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
	 security_hole(kb_smb_transport()); 
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
