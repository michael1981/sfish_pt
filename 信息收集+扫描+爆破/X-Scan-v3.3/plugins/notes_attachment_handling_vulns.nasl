#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20924);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2618", "CVE-2005-2619");
  script_bugtraq_id(16576);
  script_xref(name:"OSVDB", value:"23064");
  script_xref(name:"OSVDB", value:"23065");
  script_xref(name:"OSVDB", value:"23066");
  script_xref(name:"OSVDB", value:"23067");
  script_xref(name:"OSVDB", value:"23068");

  script_name(english:"Lotus Notes < 6.5.5 / 7.0.1 Attachment Handling Vulnerabilities");
  script_summary(english:"Checks for attachment handling vulnerabilities in Lotus Notes");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote host reportedly
contains five buffer overflow vulnerabilities and one directory
traversal vulnerability in the KeyView viewers used to handle message
attachments.  By sending specially-crafted attachments to users of the
affected application and getting them to double-click and view the
attachment, an attacker may be able to execute arbitrary code subject
to the privileges under which the affected application runs or to
delete arbitrary files that are accessible to the NOTES user." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/16280/" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21229918" );
 script_set_attribute(attribute:"solution", value:
"Either edit the 'keyview.ini' configuration file as described in the
vendor advisory above or upgrade to Lotus Notes version 6.5.5 / 7.0.1
or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/notes", 139, 445);

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
  exit(0, "cannot connect to the remote registry");
}


# Determine if it's installed.
path = NULL;

key = "SOFTWARE\Lotus\Notes";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path) {
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notes.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0, "cannot connect to the remote share");
  }

  # Determine which version of Notes is installed.
  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) {
    NetUseDel();
    exit(0, strcat("cannot read '", exe, "'"));
  }
  version = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # If it's an affected version...
  #
  # nb: version[2] is multiplied by 10.
  if (
    int(version[0]) < 6 ||
    (
      int(version[0]) == 6 &&
      (
        int(version[1]) < 5 ||
        int(version[1]) == 5 && int(version[2]) < 50
      )
    ) ||
    (
      int(version[0]) == 7 && int(version[1]) == 0 && int(version[2]) < 10
    )
  ) {
    # Read the KeyView INI file.
    ini = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\keyview.ini", string:path);
    fh = CreateFile(
      file:ini,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (isnull(fh)) {
      NetUseDel();
      exit(0, strcat("can't read '", ini, "'"));
    }
    # but no read more than 10K.
    chunk = 10240;
    size = GetFileSize(handle:fh);
    if (size > 0) {
      if (chunk > size) chunk = size;
      data = ReadFile(handle:fh, length:chunk, offset:0);
      CloseFile(handle:fh);
    }

    if (data) {
      # Affected DLLs.
      dlls = make_list("tarrdr.dll", "uudrdr.dll", "htmsr.dll");

      # Check whether affected DLLs are referenced.
      foreach dll (dlls) {
        # If so, check whether file exists.
        if (egrep(pattern:string("^[0-9]+=", dll), string:data)) {
          file =  str_replace(find:"keyview.ini", replace:dll, string:ini);
          fh = CreateFile(
            file:file,
            desired_access:GENERIC_READ,
            file_attributes:FILE_ATTRIBUTE_NORMAL,
            share_mode:FILE_SHARE_READ,
            create_disposition:OPEN_EXISTING
          );

          # There's a problem if it does.
          if (fh) {
            security_hole(port);
            CloseFile(handle:fh);
            break;
          }
        }
      }
    }
  }
}


# Clean up.
NetUseDel();
