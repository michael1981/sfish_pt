#
# This script has been rewritten by Tenable Network Security
# Original script was written by Jeff Adams <jeffadams@comcast.net>;
#
# This script is released under GPLv2
#
# Tenable grants a special exception for this plugin to use the library 
# 'smb_func.inc'. This exception does not apply to any modified version of 
# this plugin.
#


include("compat.inc");

if(description)
{
 script_id(12106);
 script_version("$Revision: 1.780 $");

 script_name(english:"Norton Antivirus Detection");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus is installed on the remote host, but it is not working
properly." );
 script_set_attribute(attribute:"description", value:
"Norton Anti-Virus, a commercial anti-virus software package for
Windows, is installed on the remote host.  However, there is a problem
with the install - either its services are not running or its engine
and/or virus definition are out-of-date." );
 script_set_attribute(attribute:"solution", value:
"Make sure updates are working and the associated services are 
running." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks that Norton Antivirus installed and then makes sure the latest Vdefs are loaded."); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Jeff Adams / Tenable Network Security, Inc."); 
 script_family(english:"Windows"); 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}

#

include("smb_func.inc");

global_var hklm;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_database_version ()
{
  local_var key, item, key_h, value, path, vers;

  key = "SOFTWARE\Symantec\SharedDefs\"; 
  item = "DEFWATCH_10"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);  
   if (!isnull (value))
     vers = value[1];
   else
   {
    item = "NAVCORP_70"; 
    value = RegQueryValue(handle:key_h, item:item);  
    if (!isnull (value))
      vers = value[1];
    else
    {
     item = "NAVNT_50_AP1"; 
     value = RegQueryValue(handle:key_h, item:item);  
     if (!isnull (value))
       vers = value[1];
     else
     {
      item = "AVDEFMGR"; 
      value = RegQueryValue(handle:key_h, item:item);  
      if (isnull (value))
      {
       RegCloseKey (handle:key_h);
       return NULL;
      }
      else
       vers = value[1];
     }
    }    
   }
   
   RegCloseKey (handle:key_h);   
  }

  key = "SOFTWARE\Symantec\InstalledApps\"; 
  item = "AVENGEDEFS"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);  
   if (!isnull (value))
     path = value[1];

   RegCloseKey (handle:key_h);
  }

  vers = substr (vers, strlen(path) + 1 , strlen(vers)-5);

  return vers;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
function check_product_version (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "version"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
     return value[1];
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
# Checks if McAfee VirusScan is installed                     #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Symantec\InstalledApps\";
item = "NAVNT";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:"SAVCE");
 if ( isnull (value) )
 {
  value = RegQueryValue(handle:key_h, item:item);
  if ( isnull (value) ) 
  {
   item = "SAVCE";
   value = RegQueryValue(handle:key_h, item:item);
  }
 }
 else
  value = NULL;

 RegCloseKey (handle:key_h);
}

if ( isnull ( value ) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);  
}

set_kb_item(name: "Antivirus/Norton/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the virus database version                           #
#-------------------------------------------------------------#

# Take the first database version key
current_database_version = check_database_version (); 
 

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (("Norton AntiVirus" >!< services) && ("Symantec AntiVirus" >!< services) && ("SymAppCore" >!< services))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

product_version = check_product_version (reg:"SOFTWARE\Symantec\Norton AntiVirus");


RegCloseKey (handle:hklm);
NetUseDel();

#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has the Norton Antivirus installed. It has been
fingerprinted as :

";

report += "Norton/Symantec Antivirus " + product_version + "
DAT version : " + current_database_version + "

";

#
# Check if antivirus database is up-to-date
#

# Last Database Version
virus = "20091119";

if ( int(current_database_version) < ( int(virus) - 1 ) )
{
  report += "The remote host has an out-dated version of the Norton
virus database. Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Norton AntiVirus is not running.

";
  warning = 1;
}


#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  report = string (
                "\n",
		report);

  security_hole(port:port, extra:report);
}
else
{
  set_kb_item (name:"Antivirus/Norton/description", value:report);
}

