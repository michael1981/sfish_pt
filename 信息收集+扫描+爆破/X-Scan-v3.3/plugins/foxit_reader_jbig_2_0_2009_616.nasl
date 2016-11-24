#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39481);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0690", "CVE-2009-0691");
  script_bugtraq_id(35442, 35443);
  script_xref(name:"OSVDB", value:"55618");
  script_xref(name:"OSVDB", value:"55619");

  script_name(english:"Foxit Reader JPEG2000 / JBIG Decoder Add-On < 2.0.2009.616 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Foxit Reader");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a PDF viewer that is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The installation of Foxit Reader on the remote host includes a version\n",
      "of the optional JPEG2000 / JBIG Decoder add-on older than\n",
      "2.0.2009.616.  Such versions reportedly are affected by the following\n",
      "vulnerabilities :\n",
      "\n",
      "  - A negative stream offset in a malicious JPX (JPEG2000)\n",
      "    stream allows reading from an out-of-bound address.\n",
      "\n",
      "  - An uncaught fatal error when decoding a JPEG2000 header\n",
      "    results in an invalid address access."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.kb.cert.org/vuls/id/251793"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.foxitsoftware.com/pdf/reader/security.htm#0602"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Foxit Reader 3.0 Build 1817 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("SMB/Foxit_Reader/Path");

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


path = get_kb_item("SMB/Foxit_Reader/Path");
if (isnull(path)) exit(0);


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


# Grab the version of the JPEG2000 / JBIG Decoder add-on.
file = "fxdecod1.dll";
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+file, string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


if (!isnull(ver))
{
  fixed_version = "2.0.2009.616";
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

        report = string(
          "  File              : ", file, " (Foxit Reader JPEG2000 / JBIG Decoder Add-On)\n",
          "  Path              : ", path, "\n",
          "  Installed version : ", version, "\n",
          "  Fix               : ", fixed_version, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
