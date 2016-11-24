#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(34363);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-2439", "CVE-2008-4402", "CVE-2008-4403");
  script_bugtraq_id(31531);
  script_xref(name:"Secunia", value:"32097"); 
  script_xref(name:"Secunia", value:"31343"); 
  script_xref(name:"OSVDB", value:"48730");
  script_xref(name:"OSVDB", value:"48801");
  script_xref(name:"OSVDB", value:"48802");

  script_name(english:"Trend Micro OfficeScan Multiple CGI Module Vulnerabilities");
  script_summary(english:"Checks for vulnerable versions of Trend Micro products");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains an application that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is either running Worry-Free Business Security or\n",
      "Trend Micro OfficeScan/Trend Micro OfficeScan client.  The installed\n",
      "version is affected by multiple vulnerabilities :\n",
      "\n",
      "  - If Trend Micro OfficeScan client 'Tmlisten.exe' is\n",
      "    configured to receive updates from other clients, it\n",
      "    may be possible to launch a directory traversal attack\n",
      "    against the remote host, and read arbitrary files.\n",
      "\n",
      "  - A vulnerability in Trend Micro OfficeScan server CGI\n",
      "    modules could be exploited to trigger a buffer overflow\n",
      "    issue and execute arbitrary code on the remote system\n",
      "    with web server privileges.\n",
      "\n",
      "  - A NULL pointer dereference issue could be exploited to\n",
      "    trigger a denial of service condition on the remote\n",
      "    system."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2008-39/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14a47516 (v7.3 Build 1372)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5493c8c (v8.0 Service Pack 1, Build 2439)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c957bae3 (v8.0 Service Pack 1 Patch 1, Build 3087)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cabe4087 (v5.0 WFBS Patch 1414)"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to :\n",
      "\n",
      " - Trend Micro OfficeScan 7.3 Build 1372.\n",
      " - Trend Micro OfficeScan 8.0 Build 2439/3087\n",
      "   depending on the current OfficeScan patch level.\n",
      " - Worry-Free Business Security 5.0 Build 1414."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

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

if (rc != 1) {
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

# Figure out the Software version

path = NULL;
server_version = NULL;
SP_version = NULL;

key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  # TrendMicro OfficeScan Server install...

  value =  RegQueryValue(handle:key_h, item:"Local_Path");
  if (!isnull(value)) path = value[1];
 
  value =  RegQueryValue(handle:key_h, item:"Server_Version");
  if (!isnull(value)) server_version = value[1];

  value =  RegQueryValue(handle:key_h, item:"ServicePack_Build");
  if (!isnull(value)) SP_version = value[1];
 
  RegCloseKey(handle:key_h);
}


# Check if Worry-Free Business Server is installed.

wfbs = 0;
key = "SOFTWARE\TrendMicro\WFBS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  wfbs = 1;
  RegCloseKey(handle:key_h);
}

if(isnull(path))
 {
   # If we reach here, we are probably looking at a client only 
   # install

   key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion";
   key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
   {
    value =  RegQueryValue(handle:key_h, item:"Application Path");
    if (!isnull(value)) path = value[1];
   }
 }

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}

# Grab the file version of tmlisten.exe

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
if("PCCSRV" >< path)
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1Pccnt\Common\Tmlisten.exe", string:path);
else
{
 exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1Tmlisten.exe", string:path);
 dll   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1NTSvcRes.dll", string:path);
}

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

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

ver_dll = NULL;
if ("PCCSRV" >!< path)
{
  # nb : Reporting client only installs based on
  #	 file version of tmlisten.exe could result in FP's.
  #	 Therefore we try to get the service pack info 
  #	 from a dll file known to indicate correct SP version
  #	 in use.
 
  fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

 if (!isnull(fh))
  {
   ver_dll = GetFileVersion(handle:fh);
   CloseFile(handle:fh);
  }
}

NetUseDel();

# Check the version number.

if (!isnull(ver_dll))
 {
   if(isnull(server_version))
   server_version = string(ver_dll[0],".",ver_dll[1]);

   if(isnull(SP_version))
   SP_version  = string(ver_dll[3]);
 }  

if (!isnull(ver))
{ 
   for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if ( # OfficeScan 7.3 without patch 1372, Tmlisten.exe file version == 7.3.0.1372 
       ( ver[0] ==  7 && ver[1] == 3 && ver[2] == 0 && ver[3] < 1372) 						       ||
       # OfficeScan 8.0 Service Pack 1 without patch 2439, Tmlisten.exe file version == 10.0.0.1222
       ( server_version == "8.0" && SP_version >= 2302 && ver[0] == 10 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1222) || 
	 # OfficeScan 8.0 Service Pack 1 Patch 1 w/o patch 3087, Tmlisten.exe file version == 10.5.0.1040
       ( server_version == "8.0" && SP_version >= 3031 && ver[0] == 10 && ver[1] == 5 && ver[2] == 0 && ver[3] < 1040) || 
	 # WorryFree 5.0 without patch 1414, Tmlisten.exe file version == 10.0.0.1220
       ( wfbs && ver[0] == 10 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1220) 
     ) 
     if (report_verbosity )
      {
	if("PCCSRV" >< path)
	  path = string(path,"Pccnt\\Common");
 
        report = string(
          "\n",
          "Version ", string(ver[0],".",ver[1],".",ver[2],".",ver[3])," of Tmlisten.exe\n", 
	  " is installed under :\n", 
          "\n",
          "  ", path,"\n"
        ); 	
      	security_hole(port:port,extra:report);
      }
      else
      	security_hole(port);
}
