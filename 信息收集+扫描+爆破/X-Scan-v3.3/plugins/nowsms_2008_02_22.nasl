#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32481);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-0871");
  script_bugtraq_id(27896);
  script_xref(name:"milw0rm", value:"5695");
  script_xref(name:"OSVDB", value:"42953");
  script_xref(name:"OSVDB", value:"42954");
  script_xref(name:"Secunia", value:"29003");

  script_name(english:"Now SMS/MMS Gateway < 2008.02.22 Multiple Remote Overflows");
  script_summary(english:"Checks version of mmsc.exe"); 

 script_set_attribute(attribute:"synopsis", value:
"A remote Windows host contains a program that is affected by multiple
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Now SMS/MMS Gateway, a tool for connecting
to SMS and/or MMS messaging providers and managing GSM modems. 

The web interface component of the version of Now SMS/MMS Gateway
installed on the remote host contains a stack-based buffer overflow
that can be triggered using a specially-crafted HTTP Authorization
request header.  An unauthenticated remote attacker can leverage this
issue to crash the affected service or to execute arbitrary code on
the affected host subject to the privileges under which the service
operates, SYSTEM by default. 

In addition, there is similar buffer overflow in the application's
SMPP server, which allocates a stack buffer of 4 KB for incoming
packets but fails to check their actual size.  By default, though,
this service is not enabled." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/nowsmsz-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.nowsms.com/discus/messages/53/23641.html" );
 script_set_attribute(attribute:"see_also", value:"http://blog.nowsms.com/2008/02/nowsms-2008-and-important-security.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Now SMS/MMS Gateway version 2008.02.22 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
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
  exit(0);
}


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Classes\SOFTWARE\NowSMS\NowSMS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDirectory");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Grab the version from mmsc.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\mmsc.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
version = NULL;
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize < 250000) off = 0;
  else off = fsize - 250000;

  while (fsize > 0 && off <= fsize && isnull(version))
  {
    data = ReadFile(handle:fh, length:16384, offset:off);
    if (strlen(data) == 0) break;
    data = str_replace(find:raw_string(0), replace:"", string:data);

    while (strlen(data) && "Now SMS/MMS Gateway v" >< data)
    {
      data = strstr(data, "Now SMS/MMS Gateway v") - "Now SMS/MMS Gateway v";
      blob = data - strstr(data, '\r\n');

      pat = "^([12][0-9]{3}\.[01][0-9]\.[0-3][0-9])$";
      if (ereg(pattern:pat, string:blob))
      {   
        version = ereg_replace(pattern:pat, replace:"\1", string:blob);
      }
      if (version) break;
    }
    off += 16383;
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("2008.02.22", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Now SMS/MMS Gateway v", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
