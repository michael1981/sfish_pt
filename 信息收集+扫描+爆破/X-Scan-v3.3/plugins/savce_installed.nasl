#
# This script has been rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# This script is released under GPLv2
#

include("compat.inc");

if(description)
{
 script_id(21725);
 script_version("$Revision: 1.595 $");
 script_name(english: "Symantec Anti Virus Corporate Edition Check");
 script_set_attribute(attribute:"synopsis", value:
"Symantec AntiVirus Corporate is installed." );
 script_set_attribute(attribute:"description", value:
"This plugin checks that the remote host has Symantec AntiVirus 
Corporate installed and properly running, and makes sure that the latest 
Vdefs are loaded." );
 script_set_attribute(attribute:"solution", value:
"Make sure SAVCE is installed, running and using the latest VDEFS." );
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Checks that SAVCE installed and then makes sure the latest Vdefs are loaded.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Jeff Adams / Tenable Network Security, Inc."); 
 script_family(english: "Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}
include("smb_func.inc");

global_var hklm, soft_path,sep;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, items, key_h, val, value, path, vers;

  path = NULL;
  vers = NULL;

  key = soft_path + "Symantec\InstalledApps\"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:"AVENGEDEFS");
   if (!isnull (value)) path = value[1];

   RegCloseKey (handle:key_h);
  }
  if (isnull(path)) return NULL;

  key = soft_path + "Symantec\SharedDefs\"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
    items = make_list(
      "DEFWATCH_10", 
      "NAVCORP_72", 
      "NAVCORP_70",
      "NAVNT_50_AP1"
    );

    foreach item (items)
    {
      value = RegQueryValue(handle:key_h, item:item);
      if (!isnull (value))
      {
        val = value[1];
        if (stridx(val, path) == 0)
        {
          val = val - (path+"\");
          if ("." >< val) val = val - strstr(val, ".");
          if (isnull(vers) || int(vers) < int(val)) vers = val;
        }
      }
    }

    RegCloseKey (handle:key_h);
  }
  if (isnull(vers)) return NULL;

  set_kb_item(name: "Antivirus/SAVCE/signature", value:vers);
  return vers;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
# Note that major version will only be reported (ie. 9.0.1000 #
#    instead of 9.0.5.1000)                                   #
# Also you can check ProductVersion in                        #
#    HKLM\SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion #
#-------------------------------------------------------------#

function check_product_version ()
{
  local_var key, item, key_h, value, directory, output, version, vhigh, vlow, v1, v2, v3;

  key = soft_path + "INTEL\LANDesk\VirusProtect6\CurrentVersion";
  item = "ProductVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( isnull(key_h) )
  {
   sep = 1;
   key = soft_path + "Symantec\Symantec Endpoint Protection\AV";
   key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  }

  if ( ! isnull(key_h) )
  {
   version = RegQueryValue(handle:key_h, item:item);

   RegCloseKey (handle:key_h);

   if (!isnull (version))
   {
    vhigh = version[1] & 0xFFFF;
    vlow = (version[1] >>> 16);

    v1 = vhigh / 100;
    v2 = (vhigh%100)/10;
    v3 = (vhigh%10);

    if ( (v1 / 10) > 1 )
    {
      v3 = (v1 / 10 - 1) * 1000;
      v1 = 10 + v1 % 10;
    }

    version = string (v1, ".", v2, ".", v3, ".", vlow);

    set_kb_item(name: "Antivirus/SAVCE/version", value:version);
    return version;
   }
  }

 return NULL;
}


#==================================================================#
# Section 2. Main code                                             #
#==================================================================#


services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

access = get_kb_item("SMB/registry_full_access");
if( ! access )exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}


#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp is installed              #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Wow6432Node\Symantec\InstalledApps\";
item = "SAVCE";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 key = "SOFTWARE\Symantec\InstalledApps\";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

 soft_path = "SOFTWARE\";
}
else
{
 soft_path = "SOFTWARE\Wow6432Node\";
}

if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}
else
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}

if ( isnull ( value ) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);  
}

set_kb_item(name: "Antivirus/SAVCE/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#

# Take the first signature version key
current_signature_version = check_signature_version (); 
 

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (("Norton AntiVirus" >!< services) && (!egrep(pattern:"\[ *Symantec AntiVirus *\]", string:services, icase:TRUE)))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
sep = 0;
product_version = check_product_version();


#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp has Parent server set     #
#-------------------------------------------------------------#

key = soft_path + "Intel\LANDesk\VirusProtect6\CurrentVersion\";
item = "Parent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 parent = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( strlen (parent[1]) <=1 )
{
  set_kb_item(name: "Antivirus/SAVCE/noparent", value:TRUE);
  RegCloseKey(handle:hklm);
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/parent", value:parent[1]);
}  


#==================================================================#
# Section 3. Clean Up                                              #
#==================================================================#

RegCloseKey (handle:hklm);
NetUseDel();

#==================================================================#
# Section 4. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has an anti-virus software from Symantec installed. It has 
been fingerprinted as :

";

if(product_version && sep)
{
report += "Symantec Endpoint Protection : " + product_version + "
DAT version : " + current_signature_version + "

";
}
else
{
report += "Symantec Antivirus Corporate : " + product_version + "
DAT version : " + current_signature_version + "

";
}

#
# Check if antivirus signature is up-to-date
#

# Last Database Version
virus = "20091119";

if ( int(current_signature_version) < ( int(virus) - 1 ) )
{
  report += "The remote host has an out-dated version of the Symantec 
Corporate virus signatures. Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Symantec AntiVirus Corporate is not running.

";
  set_kb_item(name: "Antivirus/SAVCE/running", value:FALSE);
  warning = 1;
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  security_hole(port:port, extra:'\n'+report);
}
else
{
  set_kb_item (name:"Antivirus/SAVCE/description", value:report);
}
