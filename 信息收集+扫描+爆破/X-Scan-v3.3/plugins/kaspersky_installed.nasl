#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(20284);
  script_version("$Revision: 1.693 $");

  script_name(english:"Kaspersky Anti-Virus Detection");
  script_summary(english:"Checks for Kaspersky Anti-Virus");
 
 script_set_attribute(attribute:"synopsis", value:
"An antivirus is installed on the remote host, but it is not working
properly." );
 script_set_attribute(attribute:"description", value:
"Kaspersky Anti-Virus, a commercial anti-virus software package for
Windows, is installed on the remote host.  However, there is a problem
with the install - either its services are not running or its engine
and/or virus definitions are out-of-date." );
 script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/" );
 script_set_attribute(attribute:"solution", value:
"Make sure updates are working and the associated services are running." );
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


# Connect to the remote registry.
if (!get_kb_item("SMB/registry_full_access")) exit(0);


name    = kb_smb_name();
if (!name) exit(0);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();
if (!port) port = 139;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check if the software is installed.
base_dir = NULL;
name = NULL;
path = NULL;
prodinfo = NULL;
sig_path = NULL;
upd_cfg = NULL;
ver = NULL;

# - KAV 7.0 (Internet Security / Anti-Virus / Anti-Virus for Windows Workstations / Anti-Virus for Windows Servers)
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP7\environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 6.0 (Internet Security / Anti-Virus / Anti-Virus for Windows Workstations / Anti-Virus for Windows Servers)
prod++;
prod_subkeys[prod] = "KasperskyLab\AVP6\Environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV for Windows File Servers
prod++;
prod_subkeys[prod] = "Microsoft\Windows\CurrentVersion\Uninstall\{1A694303-9A42-43A8-A831-50F86C64EDF0}";
name_subkeys[prod] = "DisplayName";
path_subkeys[prod] = "InstallLocation";
ver_subkeys[prod]  = "DisplayVersion";
# - KAV for Workstations
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus for Windows Workstations";
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";
# - KAV Personal / KAV Personal Pro
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus Personal";
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";

# - KAV / KAV IS 2010
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP9\environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";

foreach prod (keys(prod_subkeys))
{
  key = "SOFTWARE\" + prod_subkeys[prod];
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:name_subkeys[prod]);
    if (!isnull(value))
    {
      name = value[1];
      # get rid of version info in the name.
      name = ereg_replace(string:name, pattern:" [0-9.]+", replace:"");
    }

    value = RegQueryValue(handle:key_h, item:path_subkeys[prod]);
    if (!isnull(value)) path = ereg_replace(string:value[1], pattern:"\$", replace:"");

    value = RegQueryValue(handle:key_h, item:ver_subkeys[prod]);
    if (!isnull(value)) ver = value[1];

    # Figure out where to look for signature info.
    # 
    # - KAV 7/0 / 6.0/ 2010
    if (
      prod_subkeys[prod] == "KasperskyLab\protected\AVP7\environment" ||
      prod_subkeys[prod] == "KasperskyLab\AVP6\Environment"	      ||
      prod_subkeys[prod] == "KasperskyLab\protected\AVP9\environment"
    )
    {
      # Figure out where the update config is.
      value = RegQueryValue(handle:key_h, item:"UpdateRoot");
      if (!isnull(value)) 
      {
        upd_cfg = value[1];
        upd_cfg = ereg_replace(pattern:"^.+/(.+\.xml)$", replace:"\1", string:upd_cfg);
      }

      data_dir = "%DataFolder%";
      i = 0;
      while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:data_dir))
      {
        s = match[1];
        value = RegQueryValue(handle:key_h, item:s);
        if (!isnull(value))
          data_dir = str_replace(
            find:string("%", s, "%"),
            replace:value[1],
            string:data_dir
          );
        else break;

        # limit how many times we'll loop.
        if (++i > 5) break;
      }
      if (!isnull(upd_cfg) && !isnull(data_dir)) upd_cfg = data_dir + "\" + upd_cfg;

      base_dir = "%Bases%";
      i = 0;
      while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
      {
        s = match[1];
        value = RegQueryValue(handle:key_h, item:s);
        if (!isnull(value))
          base_dir = str_replace(
            find:string("%", s, "%"),
            replace:value[1],
            string:base_dir
          );
        else break;

        # limit how many times we'll loop.
        if (++i > 5) break;
      }
    }
    else 
    {
      # some products point to it in the registry.
      key2 = "SOFTWARE\KasperskyLab\Components\10a\LastSet";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Directory");
        if (!isnull(value)) sig_path = ereg_replace(string:value[1], pattern:"\$", replace:"");
      }
      RegCloseKey(handle:key2_h);

      # some products point to it from SS_PRODINFO.xml.
      key2 = "SOFTWARE\KasperskyLab\Components\34";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"SS_PRODINFO");
        if (!isnull(value)) prodinfo = ereg_replace(string:value[1], pattern:"\$", replace:"");
      }
      RegCloseKey(handle:key2_h);
    }
    RegCloseKey(handle:key_h);

    # We found a product so we're done.
    break;
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(name) || isnull(path) || isnull(ver))
{
  NetUseDel();
  exit(0);  
}

set_kb_item(name:"Antivirus/Kaspersky/installed", value:TRUE);
set_kb_item(name:"Antivirus/Kaspersky/" + name, value:ver + " in " + path);


# Figure out where signature information is stored.
update_date = NULL;

# - KAV 7.0 / 6.0
if (!isnull(upd_cfg) && !isnull(base_dir))
{
  # First, read the main updates file.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:upd_cfg);
  xml_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:upd_cfg);

  av_upd = NULL;

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      contents = ReadFile(handle:fh, offset:0, length:10240);
      contents = str_replace(string:contents, find:raw_string(0x00), replace:"");
 
      if("AVP9" >< upd_cfg && 'ComponentID="VLNS,KDBI386"' >< contents)
      { 
        # nb: File referenced by AVS component does not exist
        #     in AVP9, therefore we use file referenced by
        #     VLNS,KDBI386 to extract update date, which is
        #     accurate.
        { 
          contents = strstr(contents, 'ComponentID="VLNS,KDBI386"');
          if (contents) contents = contents - strstr(contents, ">");
          if (contents && 'Filename="' >< contents)
          { 
            av_upd = strstr(contents, 'Filename="') - 'Filename="';
            av_upd = av_upd - strstr(av_upd, '"');
          }
         }
      } 
      else if ('ComponentID="AVS"' >< contents)
      {
        contents = strstr(contents, 'ComponentID="AVS"');
        if (contents) contents = contents - strstr(contents, ">");
        if (contents && 'Filename="' >< contents)
        {
          av_upd = strstr(contents, 'Filename="') - 'Filename="';
          av_upd = av_upd - strstr(av_upd, '"');
        }
      }
      CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);
  }

  # Now grab the AV update file.
  if (!isnull(av_upd))
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:base_dir);
    xml_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+av_upd, string:base_dir);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1)
    {
      fh = CreateFile(
        file:xml_file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        contents = ReadFile(handle:fh, offset:0, length:10240);
        contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

        if ('UpdateDate="' >< contents)
        {
          contents = strstr(contents, 'UpdateDate="') - 'UpdateDate="';
          if (contents) contents = contents - strstr(contents, ">");
          if (contents && '"' >< contents)
          {
            update_date = contents - strstr(contents, '"');
          }
        }
        CloseFile(handle:fh);
      }
    }
  }
}
else
{
  if (prodinfo)
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:prodinfo);
    prodinfo_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:prodinfo);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1) {
      fh = CreateFile(
        file:prodinfo_file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        contents = ReadFile(handle:fh, offset:0, length:10240);
        contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

        # Isolate the base folder path.
        sig_path = strstr(contents, "BaseFolder");
        if (sig_path)
        {
          len = ord(sig_path[11]);
          if (sig_path) sig_path = substr(sig_path, 12, 12+len-1);
        }
      
        CloseFile(handle:fh);
      }
      NetUseDel(close:FALSE);
    }
  }

  # Make an assumption if we couldn't determine it.
  if (!sig_path)
  {
    v = split(ver, sep:'.', keep:FALSE);
    sig_path = "C:\Documents and Settings\All Users\Application Data\" + 
               name + "\" + 
               v[0] + "." + v[1] + 
               "\Bases";
  }

  # Read signature date from the file KAVSET.XML.
  # 
  # nb: this is stored typically in a hidden directory, in case one's
  #     simply looking for it.
  share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:sig_path);
  xml_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\kavset.xml", string:sig_path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      contents = ReadFile(handle:fh, offset:0, length:256);

      # Get the date from the update_date XML block.
      update_date = strstr(contents, "Updater/update_date");
      if (update_date) update_date = update_date - strstr(update_date, '" />');
      if (update_date) update_date = strstr(update_date, 'Value="');
      if (update_date) update_date = update_date - 'Value="';      
    }
    CloseFile(handle:fh);
  }
}
NetUseDel();

if (!isnull(update_date) && update_date =~ "^[0-9]+ [0-9]+$")
{
  day   = substr(update_date, 0, 1);
  month = substr(update_date, 2, 3);
  year  = substr(update_date, 4, 7);
  sigs_target = string(month, "/", day, "/", year);
}
else sigs_target = "unknown";
set_kb_item(name:"Antivirus/Kaspersky/sigs", value:sigs_target);


# Generate report
trouble = 0;

# - general info.
report = "Kaspersky Anti-Virus is installed on the remote host :

  Product Name:      " + name + " 
  Version:           " + ver + "
  Installation Path: " + path + "
  Virus signatures:  " + sigs_target + "

";

# - sigs out-of-date?
sigs_vendor_yyyymmdd = "20091120";
out_of_date = 1;
# nb: out_of_date will be 1 if sigs_target == "unknown".
if (sigs_target =~ "[0-9][0-9]/[0-9][0-9]/[0-9][0-9][0-9][0-9]")
{
  a = split(sigs_target, sep:"/", keep:0);
  sigs_target_yyyymmdd = string(a[2], a[0], a[1]);

  if (int(sigs_target_yyyymmdd) >= (int(sigs_vendor_yyyymmdd) - 1)) 
    out_of_date = 0;
}
if (out_of_date)
{
  sigs_vendor_mmddyyyy = string(
    substr(sigs_vendor_yyyymmdd, 4, 5), 
    "/",
    substr(sigs_vendor_yyyymmdd, 6, 7), 
    "/",
    substr(sigs_vendor_yyyymmdd, 0, 3)
  );

  report += "The virus signatures on the remote host are out-of-date - the last 
known update from the vendor is " + sigs_vendor_mmddyyyy + "

";
  trouble++;
}


# - services running.
services = get_kb_item("SMB/svcs");
if (
  services &&
  (
    # Kaspersky Internet Security
    "Kaspersky Internet Security" >!< services &&
    "AVP" >!< services &&
    # others
    "Kaspersky Anti-Virus" >!< services &&
    "kavsvc" >!< services
  )
) {
  report += "The remote Kaspersky Anti-Virus service is not running.

";
  trouble++;
}

if (trouble)
{
  report = string(
    "\n",
    report,
    "As a result, the remote host might be infected by viruses."
  );

  security_hole(port:port, extra:report);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/Kaspersky/description", value:report);
}
