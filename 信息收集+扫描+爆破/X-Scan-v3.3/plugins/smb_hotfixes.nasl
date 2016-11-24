#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(13855);
 script_version("$Revision: 1.49 $");

 script_name(english:"Installed Windows Hotfixes");
 script_summary(english:"Fills the KB with the list of installed hotfixes");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "It is possible to enumerate installed hotfixes on the remote Windows\n",
   "host."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "Using the supplied credentials, Nessus was able to log into the the\n",
   "remote Windows host, enumerate installed hotfixes, and store them in\n",
   "its knowledge base for other plugins to use. "
   )
 );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_registry_full_access.nasl", "smb_reg_service_pack.nasl","smb_reg_service_pack_W2K.nasl", "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access");

 script_require_ports(139, 445);
 script_timeout(600);
 exit(0);
}

if ( get_kb_item("SMB/samba") ) exit(0);

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

global_var handle;
global_var Versions;


Versions = make_array();

function crawl_for_version(key, level, maxlevel, allow)
{
 local_var mylist, entries, l, list, item, tmp, key_h, info, i, subkey;
 list = make_list();
 entries = make_list();

 if ( level >= maxlevel )
   return make_list();

 if (isnull(allow) || (allow == FALSE))
 {
  tmp = tolower (key); 
   if ( "software\classes" >< tmp || "software\wow6432node\classes" >< tmp || "software\clients" >< tmp || "software\microsoft" >< tmp || "software\odbc" >< tmp || "software\policies" >< tmp) return make_list();
 }

 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h))
 {
  info = RegQueryInfoKey(handle:key_h);
  if ( isnull(info) ) 
  {
   RegCloseKey(handle:key_h);
   return make_list();
  }

  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);
   if ( subkey == NULL ) break;
   else list = make_list(list, key + "\" + subkey);
  }

  item = RegQueryValue(handle:key_h, item:"Version");
  if ( !isnull(item) ) 
   {
   Versions[key] = item[1];
   }
  RegCloseKey(handle:key_h);
 }

 entries = make_list();
 foreach l (list)
 {
  entries = make_list(entries, crawl_for_version(key:l, level:level + 1, maxlevel:maxlevel, allow:allow));
 }

 return make_list(list, entries);
}


function crawl(key, level, maxlevel)
{
 local_var mylist, entries, l, list, key_h, info, i, subkey;
 list = make_list();
 entries = make_list();

 if ( level >= maxlevel ) return make_list();

 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h))
 {
  info = RegQueryInfoKey(handle:key_h);
  if ( isnull(info) ) 
  {
   RegCloseKey(handle:key_h);
   return make_list();
  }

  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);
   if ( subkey == NULL ) break;
   else list = make_list(list, key + "\" + subkey);
  }
  RegCloseKey(handle:key_h);
 }

 entries = make_list();
 foreach l (list)
 {
  entries = make_list(entries, crawl(key:l, level:level + 1, maxlevel:maxlevel));
 }

 return make_list(list, entries);
}

function get_key(key, item)
{
 local_var key_h, value;
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( isnull(key_h) ) return NULL;
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey(handle:key_h);
 if ( isnull(value) ) return NULL;
 else return value[1];
}


name = kb_smb_name();
if(!name)exit(0);

port = kb_smb_transport();
if(!port)exit(0);

if(!get_port_state(port)) exit(0);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();


soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:name);
ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 set_kb_item(name:"HostLevelChecks/failure", value:"it was not possible to connect to the remote registry");
 NetUseDel ();
 exit(0);
}

vers = get_kb_item("SMB/WindowsVersion");

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "SystemRoot";
data = get_key(key:key, item:item);
if ( data ) {
	set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot", value:data);
	systemroot = data;
	}


access = FALSE;
if ( systemroot )
{
 share = ereg_replace(pattern:"^([A-Z]):.*", string:systemroot, replace:"\1$");

 RegCloseKey(handle:handle);
 NetUseDel(close:FALSE);

 r = NetUseAdd(share:share);

 NetUseDel(close:FALSE);
 NetUseAdd(share:"IPC$");

 handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if ( isnull(handle) )
 {
  set_kb_item(name:"HostLevelChecks/failure", value:"it was not possible to connect to the remote registry");
  NetUseDel ();
  exit(0);
 }

 if (r == 1)  access = TRUE;
}

if (access != TRUE)
{
   report = '
The SMB account used for this test does not have sufficient privileges to get
the list of the hotfixes installed on the remote host. As a result, Nessus was
not able to determine the missing hotfixes on the remote host and most SMB checks
have been disabled.

Solution : Configure the account you are using to get the ability to connect to ADMIN$';
 set_kb_item(name:"HostLevelChecks/failure", value:"the account used does not have sufficient privileges to read all the required registry entries");
   security_note(port:0, data:report);
   RegCloseKey(handle:handle);
   NetUseDel();
   exit(1);
}


# Make sure it is a 32bits system
arch = '';

key_h = RegOpenKey(handle:handle, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 item = RegQueryValue(handle:key_h, item:"PROCESSOR_ARCHITECTURE");
 if (!isnull(item))
 {
   arch = item[1];
   if ("64" >< arch) arch = "x64";
   else arch = "x86";

   set_kb_item(name:"SMB/ARCH", value:arch);
 }

 RegCloseKey(handle:key_h);
}

if ("x86" >!< arch && vers !~ "^([6-9]\.|5\.2)" )
{
 RegCloseKey(handle:handle);
 NetUseDel();
 exit(1);
}



crawl_for_version(key:"SOFTWARE\Microsoft\Active Setup\Installed Components", level:0, maxlevel:2, allow:TRUE);
foreach k (keys(Versions))
{
 s = str_replace(find:"\", replace:"/", string:k);
 if ( ! isnull(Versions[k]) )
  set_kb_item(name:"SMB/Registry/HKLM/" + s + "/Version", value:Versions[k]);
}


#
# Check for common registry values other plugins are likely to look at
# 
key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions", value:value);


key = "SYSTEM\CurrentControlSet\Services\W3SVC";
item = "ImagePath";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath", value:value);

key = "SOFTWARE\Microsoft\DataAccess";
item = "Version";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/DataAccess/Version", value:value);

# Exchange detection

key = "SOFTWARE\Microsoft\Exchange\Setup";
item = "Services";
value = get_key(key:key, item:item);
if ( value )
{
 set_kb_item(name:"SMB/Exchange/Path", value:value);

 item = "Services Version";
 value = get_key(key:key, item:item);
 if ( value )
 {
  set_kb_item(name:"SMB/Exchange/Version", value:value);

  item = "ServicePackNumber";
  value = get_key(key:key, item:item);
  if ( value )
  {
   set_kb_item(name:"SMB/Exchange/SP", value:value);
  }
 }
 else
 {
  item = "MsiProductMajor";
  value = get_key(key:key, item:item);
  if ( value )
  {
   value = value*10;
   set_kb_item(name:"SMB/Exchange/Version", value:value);

   item = "MsiProductMinor";
   value = get_key(key:key, item:item);
   if ( value )
   {
    set_kb_item(name:"SMB/Exchange/SP", value:value);
   }
  }
 }

 item = "Web Connector";
 value = get_key(key:key, item:item);
 if ( value )
 {
  set_kb_item(name:"SMB/Exchange/OWA", value:TRUE);
 }
}

key = "SYSTEM\CurrentControlSet\Services\DHCPServer";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DHCPServer", value:1);
 RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\SMTPSVC";
item = "DisplayName";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SMTPSVC/DisplayName", value:value);

key = "SYSTEM\CurrentControlSet\Services\SNMP";
item = "DisplayName";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SNMP/DisplayName", value:value);

key = "SYSTEM\CurrentControlSet\Services\WINS";
item = "DisplayName";
data = get_key(key:key, item:item);
if ( data )  set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName", value:data);

key = "SYSTEM\CurrentControlSet\Services\DNS";
item = "DisplayName";
data = get_key(key:key, item:item);
if ( data )  set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName", value:data);

key = "SOFTWARE\Microsoft\DirectX";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version", value:data);


# Check Visio version

key = "SOFTWARE\Microsoft\Office\12.0\Visio\InstallRoot";
item = "Path";

value = get_key(key:key, item:item);
if ( value ) 
{
 set_kb_item(name:"SMB/Office/Visio", value:"12.0");
 set_kb_item(name:"SMB/Office/VisioPath", value:value);
}
else
{
 key = "SOFTWARE\Microsoft\Visio\Installer";
 item = "Visio10InstallLocation";

 value = get_key(key:key, item:item);
 if ( value ) 
 {
  set_kb_item(name:"SMB/Office/Visio", value:"10.0");
  set_kb_item(name:"SMB/Office/VisioPath", value:value);
 }
 else
 {
  key = "SOFTWARE\Microsoft\Office\11.0\Visio";
  item = "CurrentlyRegisteredVersion";

  value = get_key(key:key, item:item);
  if ( value ) 
  {
   set_kb_item(name:"SMB/Office/Visio", value:"11.0");

   # Visio path is not in the registry ....
   visio_path = NULL;

   key = "SOFTWARE\Microsoft\Office\11.0\Common\InstallRoot";
   item = "Path";

   value = get_key(key:key, item:item);
   if ( value ) 
   {
    if (egrep(pattern:"^.*OFFICE11.*", string:value))
    {
     value = ereg_replace(pattern:"^(.*)OFFICE11.*", string:value, replace:"\1");
    }
    visio_path = value;
   }

   if (isnull(visio_path))
   {
     key = "SOFTWARE\Microsoft\Office\11.0\InfoPath\InstallRoot";
     item = "Path";

     value = get_key(key:key, item:item);
     if ( value ) 
     {
      if (egrep(pattern:"^.*OFFICE11.*", string:value))
      {
       value = ereg_replace(pattern:"^(.*)OFFICE11.*", string:value, replace:"\1");
      }
      visio_path = value;
    }

    if (!isnull(visio_path)) 
      set_kb_item(name:"SMB/Office/VisioPath", value:visio_path);
   }
  }
 }
}


# Check Office products

office_products = make_list("Outlook", "Word", "Excel", "Powerpoint", "Publisher");
office_versions = make_list("12.0", "11.0", "10.0", "9.0", "8.0");

# Grab info about service pack upgrades, if available.
foreach version (office_versions)
{
  key = "SOFTWARE\Microsoft\Office\" + version + "\Common\ProductVersion";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   item = RegQueryValue(handle:key_h, item:"LastProduct");
   if (!isnull(item))
   {
     last_product = item[1];
     set_kb_item(name:"SMB/Office/"+version+"/LastProduct", value:last_product);
   }
   RegCloseKey(handle:key_h);
  }
}

foreach product (office_products)
{
 foreach version (office_versions)
 {
  key = "SOFTWARE\Microsoft\Office\" + version + "\" + product + "\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   path = RegQueryValue(handle:key_h, item:"Path");
   if (!isnull(path))
     set_kb_item(name:"SMB/Office/"+product+"/Path", value:path[1]);

   RegCloseKey(handle:key_h);
   set_kb_item(name:"SMB/Office/"+product, value:version);
   break; # -> next product
  }
 }
}

# Check Office Viewers

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{90840409-6000-11D3-8CFE-0150048383C9}";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 version = RegQueryValue(handle:key_h, item:"DisplayVersion");
 if (!isnull(version))
 {
  version = ereg_replace(pattern:"^([0-9]+\.[0-9]+)\..*", string:version[1], replace:"\1");
  path = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(path))
    set_kb_item(name:"SMB/Office/ExcelViewer/Path", value:path[1]);

  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/ExcelViewer", value:version);
 }
}
 
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{90850409-6000-11D3-8CFE-0150048383C9}";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 version = RegQueryValue(handle:key_h, item:"DisplayVersion");
 if (!isnull(version))
 {
  version = ereg_replace(pattern:"^([0-9]+\.[0-9]+)\..*", string:version[1], replace:"\1");
  path = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(path))
    set_kb_item(name:"SMB/Office/WordViewer/Path", value:path[1]);

  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/WordViewer", value:version);
 }
}


key = "SOFTWARE\Microsoft\Internet Explorer";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/IE/Version", value:data);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
item = "Shell";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/Shell", value:data);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "ProgramFilesDir";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir", value:data);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "ProgramFilesDir (x86)";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86", value:data);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "CommonFilesDir";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDir", value:data);

# Works detection.
key = "SOFTWARE\Microsoft\Works";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  version = NULL;
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:handle, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"CurrentVersion");
        if (!isnull(value))
        {
          version = value[1];
          set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Works", value:TRUE);
          set_kb_item(name:"SMB/Works/Version", value:version);
        }
        RegCloseKey(handle:key2_h);
      }
    }
    if (!isnull(version)) break;
  }
  RegCloseKey(handle:key_h);
}

key = "SOFTWARE\Microsoft\Fpc";
item = "InstallDirectory";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc", value:data);

key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}";
item = "IsInstalled";
data = get_key(key:key, item:item);
if ( data )
{
 item = "Version";
 data = get_key(key:key, item:item);
 if ( data ) set_kb_item(name:"SMB/WindowsMediaPlayer", value:data);
}

key = "SOFTWARE\Microsoft\MediaPlayer";
item = "Installation Directory";
data = get_key(key:key, item:item);
if ( data )
{
 set_kb_item(name:"SMB/WindowsMediaPlayer_path", value:data);
}

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\5.0";
item = "Location";
data = get_key(key:key, item:item);
if ( data )
{
 set_kb_item(name:"Frontpage/2002/path", value:data);
}


key = "SOFTWARE\Microsoft\Internet Explorer";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version", value:data);

key = "SOFTWARE\Microsoft\Internet Explorer\Version Vector";
item = "IE";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version Vector/IE", value:data);

key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
item = "MinorVersion";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion", value:data);



key  = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{03D9F3F2-B0E3-11D2-B081-006008039BF0}";
item = "Compatibility Flags";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{03D9F3F2-B0E3-11D2-B081-006008039BF0}", value:data);

key  = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{00000566-0000-0010-8000-00AA006D2EA4}";
item = "Compatibility Flags";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags", value:data);


key = "SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent\SubSystems";
item = "CmdExec";
data = get_key(key:key, item:item);
if ( data ) 
{
 path =  ereg_replace(pattern:"^([A-Za-z]:.*)\\sqlcmdss\.(DLL|dll).*", replace:"\1", string:data);
 if ( path ) set_kb_item (name:"MSSQL/Path", value:path);
}

set_kb_item(name:"SMB/Registry/Enumerated", value:TRUE);
#
# Check for Uninstall
#

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if(!isnull(key_h))
{
 info = RegQueryInfoKey(handle:key_h);
 if (!isnull(info)) 
 {
  for (i=0; i<info[1]; i++)
  {
   subkey = RegEnumKey(handle:key_h, index:i);

   key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED);
   if (!isnull (key_h2))
   {
    value = RegQueryValue(handle:key_h2, item:"DisplayName");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\DisplayName";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayVersion";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }
    RegCloseKey (handle:key_h2);
   }
  }
 }
 RegCloseKey(handle:key_h);
}


if ( arch == "x64" )
{
key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED, wow:FALSE);
if(!isnull(key_h))
{
 info = RegQueryInfoKey(handle:key_h);
 if ( !isnull(info) ) 
 {
  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);

   key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED, wow:FALSE);
   if (!isnull (key_h2))
   {
    value = RegQueryValue(handle:key_h2, item:"DisplayName");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\DisplayName";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      name -= "Wow6432Node/";
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayVersion";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      name -= "Wow6432Node/";
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }
    RegCloseKey (handle:key_h2);
   }
  }
 }
 RegCloseKey(handle:key_h);
 }
}

RegCloseKey(handle:handle);
NetUseDel(close:FALSE);


file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:systemroot + "\system32\prodspec.ini");
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:systemroot);



ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( ret != 1 ) exit(0);



handle = CreateFile(         file:file,
		   desired_access:GENERIC_READ,
		  file_attributes:FILE_ATTRIBUTE_NORMAL,
		       share_mode:FILE_SHARE_READ,
		     create_disposition:OPEN_EXISTING);
			
if ( ! isnull(handle) ) 
{
 resp = ReadFile(handle:handle, length:16384, offset:0);
 CloseFile(handle:handle);
 resp =  str_replace(find:'\r', replace:'', string:resp);
 set_kb_item(name:"SMB/ProdSpec", value:resp);
}


NetUseDel(close:TRUE);
