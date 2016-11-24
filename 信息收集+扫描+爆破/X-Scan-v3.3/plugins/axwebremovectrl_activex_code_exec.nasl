#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20297);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3693");
  script_xref(name:"OSVDB", value:"20950");

  script_name(english:"AxWebRemoveCtrl ActiveX Control Arbitrary Code Execution");
  script_summary(english:"Checks for remote code execution vulnerability in AxWebRemoveCtrl ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is prone to remote
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control from SunnComm called
AxWebRemoveCtrl.  This control was likely installed by requesting an
uninstaller for SunnComm's MediaMax digital rights management software
used, for example, on select Sony CDs. 

By design, AxWebRemoveCtrl allows any web site to cause the control to
download and execute code from an arbitrary URL.  Should a user visit
a maliciously-crafted website, this would allow that website to
execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.freedom-to-tinker.com/?p=931" );
 script_set_attribute(attribute:"see_also", value:"http://www.sunncomm.com/support/faq/" );
 script_set_attribute(attribute:"solution", value:
"On the affected host, remove the file 'AxWebRemoveCtrl.ocx', and
reboot." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine if the control is installed.
clid = "1F1EB85B-0FE9-401D-BC53-10803CF880A7";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) name = value[1];
  else name = NULL;

  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is...
if (name && "AxWebRemoveCtrl" >< name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{" + clid + "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      file = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # Generate the report.
  if (file && report_verbosity > 0) {
    report = string(
      "The AxWebRemoveCtrl ActiveX control is installed as \n",
      "\n",
      "  ") + file + '\n';
  }
  else report = NULL;

  security_hole(port:port, extra:report);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
