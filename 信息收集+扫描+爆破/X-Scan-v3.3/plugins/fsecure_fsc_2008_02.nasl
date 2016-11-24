#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(31682);
  script_version("$Revision: 1.4 $");
  script_bugtraq_id(28282);
  script_xref(name:"OSVDB", value:"43222");
  script_cve_id("CVE-2008-1412");

  script_name(english:"F-Secure Archive Handling Vulnerabilities (FSC-2008-2)");
  script_summary(english:"Checks for archive handling vulnerabilities in F-Secure products");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote anti-virus software is affected by multiple archive handling 
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an anti-virus software application from
F-Secure. 

The version of F-Secure anti-virus installed on the remote Windows
host fails to handle specially crafted archives. An attacker can leverage 
this issue to crash the application or to execute arbitrary code remotely 
subject to local SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/" );
 script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/security/fsc-2008-2.shtml" );
 script_set_attribute(attribute:"solution", value:
"Enable auto-updates if using F-Secure Internet Security 2006-08.
Otherwise, apply the appropriate hotfix as listed in
the vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

name    = kb_smb_name();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  exit(0);
}

path = NULL;

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
 NetUseDel();
 exit (0);
}

key = "SOFTWARE\Data Fellows\F-Secure\Anti-Virus";
item = "Path";

hkey = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(hkey))
 {
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
    path = value[1];
  RegCloseKey (handle:hkey);
 }
 else
   path = NULL;

RegCloseKey (handle:hklm);
NetUseDel ();

if(isnull(path)) exit(0);

vulnerable = FALSE;
if (!isnull(path) && is_accessible_share())
 {
  # Couple of dll files get updated after applying the patch.
  if ( hotfix_check_fversion(file:"fm4av.dll", version:"1.9.14082.6716", path:path) == HCF_OLDER )
    vulnerable = TRUE;
  else if ( hotfix_check_fversion(file:"fslfpi.dll", version:"2.4.4.0", path:path) == HCF_OLDER )
    vulnerable = TRUE;
  hotfix_check_fversion_end();
 }  

if (vulnerable == TRUE)
  security_hole(port);
