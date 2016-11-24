#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(18491);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(13955);
  script_xref(name:"OSVDB", value:"17342");
  script_name(english:"ISA Server 2000 May Send Basic Credentials Over an External HTTP Connection (821724)");
  script_summary(english:"Checks for a registry key");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote service is vulnerable to information disclosure."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote ISA server is configured in such a way that it may send Basic
authentication credentials over an insecure connection."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to the latest version of ISA or apply the patch referenced in KB821724."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://support.microsoft.com/?id=821724"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

# Is ISA installed ?
fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);


name	= kb_smb_name();
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

key = "SYSTEM\CurrentControlSet\Services\W3Proxy\Parameters";
item = "DontAskBasicAuthOverNonSecureConnection";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
  value = RegQueryValue(handle:key_h, item:item);

RegCloseKey (handle:hklm);
NetUseDel();

if ( isnull(value) || value[1] == 0 ) security_warning(get_kb_item("SMB/transport"));
