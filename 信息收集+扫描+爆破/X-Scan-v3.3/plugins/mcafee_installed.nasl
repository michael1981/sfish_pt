#
# This script has been rewritten by Tenable Network Security
# Original script was written by Jeff Adams <jeffadams@comcast.net>;
#


include("compat.inc");

if(description)
{
 script_id(12107);
 script_version("$Revision: 1.739 $");

 script_name(english:"McAfee Antivirus Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote antivirus is not up to date." );
 script_set_attribute(attribute:"description", value:
"The remote host is running McAfee VirusScan Antivirus. The remote
version of this software is not up to date (engine and/or virus
definitions).
It may allow an infection of the remote host by a virus or a
worm." );
 script_set_attribute(attribute:"solution", value:
"Update your virus Definitions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks that the remote host has McAfee Antivirus installed and then makes sure the latest Vdefs are loaded."); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc."); 
 script_family(english:"Windows"); 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}


include("smb_func.inc");

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_engine_version (reg)
{
  local_var key, item, key_h, version, value, value1;
  global_var hklm;

  key = reg; 
  item = "szEngineVer"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);

   if (!isnull (value))
   {
    version = split(value[1], sep:".", keep:FALSE);
    return int(version[0]) * 1000 + int(version[1]) * 100 + int(version[2]);
   }
   else
   {
     # In version 8.5.0.275, engine version is stored here 
     value  = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
     value1 = RegQueryValue(handle:key_h, item:"EngineVersionMinor");

     # In newer versions (v8.5i ++) this is stored in ...
     if(isnull(value))
     value  = RegQueryValue(handle:key_h, item:"EngineVersion32Major");

     # In 64 bit systems it is stored in EngineVersion64Major DKO-22286-986
     if(isnull(value))
       value  = RegQueryValue(handle:key_h, item:"EngineVersion64Major");
     
     if (isnull(value1) )
	value1 = RegQueryValue(handle:key_h, item:"EngineVersion32Minor");

     # In 64 bit systems it is stored in EngineVersion64Major DKO-22286-986
     if(isnull(value1))
       value1  = RegQueryValue(handle:key_h, item:"EngineVersion64Minor");

     # If we find useful info send it back.
     if (!isnull (value) && !isnull(value1))
      {
   	RegCloseKey (handle:key_h);
        return string(value[1],".",value1[1]);
      }
   }

   RegCloseKey (handle:key_h);
  }
  return NULL;
}


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#
function check_database_version (reg)
{
  local_var key, item, key_h, value, vers, version;

  key = reg; 
  item = "szVirDefVer"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   if (isnull (value))
   {
    item = "szDatVersion";
    value = RegQueryValue(handle:key_h, item:item);
   }
 
   # In v8.5i this can be obtained from here..
   if(isnull(value)) 
   {
    value = RegQueryValue(handle:key_h, item:"AVDatVersion");
   } 

   RegCloseKey (handle:key_h);

   if (!isnull (value))
   {
    vers = value[1];

    if ( "4.0." >< vers)
    {
      version = split(vers, sep:".", keep:FALSE);
      vers = version[2];
      return vers;
    }
    else
      return vers;
   }
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#
function check_database_date (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "szVirDefDate"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   if (isnull (value))
   {
    item = "szDatDate";
    value = RegQueryValue(handle:key_h, item:item);
   }
   # In v8.5i this info is located here ..  
    if (isnull (value))
   {
    item = "AVDatDate";
    value = RegQueryValue(handle:key_h, item:item);
   }
  
   RegCloseKey (handle:key_h);

   if (!isnull (value))
      return value[1];
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
function check_product_version (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "szProductVer"; 
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

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#
function check_product_name (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "Product"; 
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
if ( ! access ) exit(0);

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

keys = make_list("SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx",
	 	 "SOFTWARE\McAfee\AVEngine");
item = "DAT";

foreach key(keys)
{
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h)) break;
}

if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

key_item = RegQueryValue(handle:key_h, item:item);
RegCloseKey(handle:key_h);
if(isnull(key_item)) 
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = key_item[1];

# Save in the registry. Can be used by another plugin
# Idea from Noam Rathaus
set_kb_item(name: "Antivirus/McAfee/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#

# Take the first engine version key
engine_version1 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx"); 

# Take the second engine version key
engine_version2 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion"); 

# We keep the more recent version

current_engine_version = NULL;

if ( engine_version1 < engine_version2 )
  current_engine_version = engine_version2;
else
  current_engine_version = engine_version1;

# Check if we can get engine version from a registry key found in v8.5i 
# or 
# If v85i_engine_version is greater than current_engine_version 
# then set current_engine_version to v85i_engine_version (#DKO-22286-986)

v85i_engine_version = NULL;
v85i_engine_version = check_engine_version (reg:"SOFTWARE\McAfee\AVEngine");

if ((!current_engine_version && !isnull(v85i_engine_version)) ||
    (!isnull(v85i_engine_version) && current_engine_version < v85i_engine_version)
   )
 {
  current_engine_version = v85i_engine_version;
 }

#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#

# Initialize var
database_version1 = database_version2 = 0;

# Take the first database version key
database_version1 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion"); 

# Take the second database version key
database_version2 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx"); 

# We keep the more recent version
if ( int(database_version1) < int(database_version2) )
{
  current_database_version = database_version2;
  new_database = 0;
}
else
{
  current_database_version = database_version1;
  new_database = 1;
}

# v8.5i ...
v85i_database_version =  check_database_version (reg:"SOFTWARE\McAfee\AVEngine");

if ((!current_database_version && !isnull(v85i_database_version)) ||
    (!isnull(v85i_database_version) && current_database_version < v85i_database_version) 
   )
 {
  current_database_version = v85i_database_version;
  if(current_database_version) new_database = 1;
 }

# Save the DAT version in KB for other plugins.
if(current_database_version)
  set_kb_item (name:"Antivirus/McAfee/dat_version", value:current_database_version);

#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#

if (new_database)
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx");

# v8.5i ...
if (!database_date)
 {
  database_date = check_database_date (reg:"SOFTWARE\McAfee\AVEngine");
 }


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

if (new_database)
  product_version = check_product_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  product_version = NULL;

# v8.5i ...
if (!product_version)
 {
  product_version = check_product_version (reg:"SOFTWARE\McAfee\DesktopProtection");
 } 


#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#

if (new_database)
  product_name = check_product_name (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  product_name = NULL;

# v8.5i ...
if(!product_name)
{
  product_name = check_product_name (reg:"SOFTWARE\McAfee\DesktopProtection");
}


#-------------------------------------------------------------#
# Checks if ePolicy Orchestror Agent is present               #
#-------------------------------------------------------------#

key = "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent"; 
item = "Installed Path";

epo_installed = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (! isnull(key_h) )
{
 epo_installed = RegQueryValue(handle:key_h, item:item);
 if (!isnull(epo_installed))
   epo_installed = epo_installed[1];
 RegCloseKey(handle:key_h);
}

if (epo_installed)
  set_kb_item(name: "Antivirus/McAfee/ePO", value:TRUE);

RegCloseKey (handle:hklm);

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

running = 1;

sc = OpenSCManager (access_mode:SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
if (!isnull (sc))
{
 service = OpenService (handle:sc, service:"McShield", access_mode:SERVICE_QUERY_STATUS);
 if (!isnull (service))
 {
  status = QueryServiceStatus (handle:service);
  if (!isnull (status))
  {
   if (status[1] != SERVICE_RUNNING)
     running = 0;
  }
  CloseServiceHandle (handle:service);
 }
 CloseServiceHandle (handle:sc);
}

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
The remote host has the McAfee antivirus installed.

";

if (product_name)
{
  report += "It has been fingerprinted as : 
";
  report += product_name + " : " + product_version + "
";
}

report += "Engine version : " + current_engine_version + "
DAT version : " + current_database_version + "
Updated date : " + database_date + "
";

if (epo_installed)
{
report += "ePO Agent : installed.

";
}
else
{
report += "ePO Agent : not present.

";
}


#
# Check if antivirus engine is up-to-date
#

# Last Engine Version
last_engine_version = 4400; # 4.4.00

if (current_engine_version < last_engine_version)
{
  report += "The remote host has an out-dated version of the McAfee
virus engine. Latest version is " + last_engine_version + "

";
  warning = 1;
}

#
# Check if antivirus database is up-to-date
#

# Last Database Version
datvers="5807";

if ( int(current_database_version) < int(datvers) )
{
  report += "The remote host has an out-dated version of the McAfee
virus database. Latest version is " + datvers + "

";
  warning = 1;
}




#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote McAffee antivirus is not running.

";
  warning = 1;
}




#
# Create the final report
#

if (warning)
{
 report = string ("\n", report);

 security_hole(port:port, data:report);
}
else
{
  set_kb_item (name:"Antivirus/McAfee/description", value:report);  
}

