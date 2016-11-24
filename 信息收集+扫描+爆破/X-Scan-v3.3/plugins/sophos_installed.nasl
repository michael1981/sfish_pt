#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) 
{
  script_id(12215);
  script_version("$Revision: 1.369 $");

  script_name(english:"Sophos Anti-Virus detection");
  script_summary(english:"Checks for Sophos Anti-Virus"); 

 script_set_attribute(attribute:"synopsis", value:
"An antivirus is installed on the remote host, but it is not working
properly." );
 script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus, a commercial anti-virus software package for
Windows, is installed on the remote host.  However, there is a problem
with the install - either its services are not running or its engine
and/or virus definition are out of date." );
 script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/" );
 script_set_attribute(attribute:"solution", value:
"Make sure updates are working and the associated services are
running." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


if (!get_kb_item("SMB/registry_full_access")) exit(0);


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

key = "SOFTWARE\Sophos\SAVService\Application";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

    set_kb_item(name:"Antivirus/Sophos/installed", value:TRUE);
  }
  RegCloseKey(handle:key_h);
}

update_path = NULL;

key = "SOFTWARE\Sophos\AutoUpdate";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Data Path");
  if (!isnull(value))
  {	
    update_path = value[1];
    update_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:update_path);
  }

  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Determine the software version.
prod_ver = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  # Use the installer's registry settings.
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Sophos Anti-Virus" >< prod)
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);

      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"DisplayVersion");
        if (!isnull(value)) prod_ver = value[1];
        RegCloseKey(handle:key_h);
      }
      if (!isnull(prod_ver)) break;
    }
  }
}
RegCloseKey(handle:hklm);


# Find the engine version from veex.dll
eng_ver = NULL;

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\veex.dll", string:path);
if(update_path)
  status_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\data\status\status.xml", string:update_path);
else
  status_file =  ereg_replace(pattern:"^[A-Za-z]:(.+)\Sophos Anti-Virus", replace:"\1\AutoUpdate\data\status\status.xml", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll_file,
  desired_access:GENERIC_READ,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

 if (!isnull(fh))
 {
   v = GetFileVersion(handle:fh);
   CloseFile(handle:fh);

   if (!isnull(v))
   {
    eng_ver = string(v[0],".",v[1],".",v[2],".",v[3]);
   }
 }
 
 CloseFile(handle:fh);
   
# Now get the last update date from status.xml

last_update_date = NULL;

 fh = CreateFile(
    file               : status_file,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize > 10240) fsize = 10240;
    if (fsize)
    {
      data = ReadFile(handle:fh, length:fsize, offset:0);
      if (data && '<LastConnectedTime>' >< data)
      {
        last_update_date = strstr(data, '<LastConnectedTime>') - '</LastConnectedTime>';
  	last_update_date = last_update_date - strstr(last_update_date, '\n'); 
 	if (last_update_date) 
	 { 
  	  last_update_date = chomp(last_update_date);
  	  last_update_date = ereg_replace(pattern:"^<LastConnectedTime>([0-9]{8})[A-Z][0-9]+$",string:last_update_date, replace: "\1");
	 } 
      }
     }
   }

 CloseFile(handle:fh);

NetUseDel();


# Generate report.
trouble = 0;
latest_prod_ver = "7.6.12";
update_date = "20091120";
latest_eng_ver = "2.75.4";

# - general info.
info = 'Sophos Anti-Virus is installed on the remote host :\n' +
       '\n' +
       '  Installation path : ' + path + '\n';
if (prod_ver)
{
  info += '  Product version   : ' + prod_ver + '\n';
  set_kb_item(name:"Antivirus/Sophos/prod_ver", value:prod_ver);
}
if (eng_ver)
{
  info += '  Engine version    : ' + eng_ver  + '\n';
  set_kb_item(name:"Antivirus/Sophos/eng_ver", value:eng_ver);
}

info += '  Virus signatures last updated   : ';
if (last_update_date) info += string(substr(last_update_date, 0, 3),"/",substr(last_update_date, 4, 5), "/",substr(last_update_date, 6, 7)) + '\n';
else info += 'never\n';

# - product out of date?
if (!isnull(prod_ver))
{
  ver = split(prod_ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split(latest_prod_ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (!isnull(fix[i]) && ver[i] < fix[i])
    {
      info += '\n' +
              'The product installed on the remote host is out-of-date - the last\n' +
              'known update from the vendor is ' + latest_prod_ver + '.\n';
      trouble++;
      break;
    }
    else if (isnull(fix[i]) || ver[i] > fix[i])
      break;
}
# - virus signatures out of date?
if (!isnull(last_update_date))
{
    # Report if the difference is more than 3 days.	
    if ( (int(update_date) - int(last_update_date)) >= 3)
    {
      trouble++;	
      info += '\n' +
              'The virus signatures on the remote host are out-of-date by at least 3 days\n' +
              'The last update from the vendor was on ' + 
	      string(substr(update_date, 0, 3),"/",substr(update_date, 4, 5), "/",substr(update_date, 6,7)) + '.\n';
    }
}
else
{
    trouble++;	
    info += '\n' +
            'The virus signatures on the remote host have never been updated!\n' +
            'The last update from the vendor was on ' + 
             string(substr(update_date, 0, 3),"/",substr(update_date, 4, 5), "/",substr(update_date, 6,7)) + '.\n';
}

# engine version out of date

if (!isnull(eng_ver))
{
  ver = split(eng_ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split(latest_eng_ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (!isnull(fix[i]) && ver[i] < fix[i])
    {
      info += '\n' +
              'The engine version on the remote host is out-of-date - the last\n' +
              'known update from the vendor is ' + latest_eng_ver + '.\n';
      trouble++;
      break;
    }
    else if (isnull(fix[i]) || ver[i] > fix[i])
      break;
}

# - services running.
services = get_kb_item("SMB/svcs");
if (services && ("SAVService" >!< services))
{
  info += '\n' +
          'The Sophos Anti-Virus service (SAVService) is not running.\n';
  trouble++;
}

if (trouble) info += '\n' +
                     'As a result, the remote host might be infected by viruses.\n';

if (trouble)
{
  report = string(
    "\n",
    info
  );
  security_hole(port:port, extra:report);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/Sophos/description", value:info);
}
