#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22411);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-4616");
  script_bugtraq_id(20091);
  script_xref(name:"OSVDB", value:"28944");

  script_name(english:"MailEnable SMTP Connector Service SPF Record Crafted Lookup DoS");
  script_summary(english:"Checks version of MailEnable's MESMTPC.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a denial of service flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MailEnable, a commercial mail server for
Windows. 

The SMTP server bundled with the version of MailEnable installed on
the remote host reportedly suffers from a flaw in which SPF lookups
for domains with large records may result in a null pointer exception
in the SMTP service.  An unauthenticated remote attacker may be able
to exploit this issue to crash the affected service." );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix ME-10014." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/smtp", 25, 139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smtp_func.inc");


smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) port = 25;
if (!get_port_state(smtp_port)) exit(0);
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);


# Make sure the banner corresponds to MailEnable.
banner = get_smtp_banner(port:smtp_port);
if (
  !banner ||
  !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)
) exit(0);


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);


session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0, "cannot connect to the remote registry");
}


# Determine location of MailEnable's application directory.
path = NULL;
key = "SOFTWARE\Mail Enable\Mail Enable";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Application Directory");
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Check version of MESMTPC.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\MESMTPC.exe", string:path);

if (
  is_accessible_share(share:share) &&
  hotfix_check_fversion(file:"MESMTPC.exe",  path:path, version:"1.0.0.20") == HCF_OLDER
) security_warning(smtp_port);

hotfix_check_fversion_end();
