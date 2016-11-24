#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35730);
  script_version("$Revision: 1.4 $");
	
  script_name(english:"Windows USB Device Usage Report");
  script_summary(english:"Checks for Historic USB device usage"); 
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to get a list of USB devices that may have been 
connected to the remote system in the past." );
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, this
plugin enumerates USB devices that have been connected to the remote
host in the past." );
 script_set_attribute(attribute:"see_also", value:
"http://www.forensicswiki.org/wiki/USB_History_Viewing" );
 script_set_attribute(attribute:"solution", value:
"Make sure that the use of USB drives is in accordance with your
organization's security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","smb_reg_service_pack.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

vista_or_later = 0;

version = get_kb_item("SMB/WindowsVersion");
if(!isnull(version))
{
  v = split(version, sep:".",keep:FALSE);
  if(v[0] && int(v[0]) >= 6)
  vista_or_later = 1;
}

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

device = NULL;
devices = make_list();
hwids 	= make_list();

key = "SYSTEM\CurrentControlSet\Enum\USBSTOR";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey))
    {   
      key2 = key + "\" + subkey;	
      key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        
      if(!isnull(key_h2))	
      {
        info2 =  RegQueryInfoKey(handle:key_h2);  	  	
        for(j=0 ; j< info2[1] ; j++)
        {
          subkey2 = RegEnumKey(handle:key_h2, index:j);
	  if (strlen(subkey2))
          {
            key3 = key2 + "\" + subkey2 ;
	    key_h3 = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
	    if (!isnull(key_h3))
            {
	      value = RegQueryValue(handle:key_h3, item:"HardwareID");
              if(!isnull(value))
              {
                hid = value[1];
		hid = tolower(hid);
	 	hid = str_replace(find:'\0', replace:'.', string:hid);	
	   	device = string("HardwareID : ",hid,'##\n'); 
                
                 if(vista_or_later)
                {
                  # For vista or later we do not rely on 'hid' to extract the
                  # time associated with device install. Its easier to match
                  # device install time with id extracted from 'key3' instead.
 
                  hid = ereg_replace(pattern:"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\(.+)",string:key3,replace:"\1");
                  hid = tolower(hid);
                  device = string("HardwareID : ",hid,'##\n');
                }

		hwids = make_list(hwids,hid);
	      }     	

	      value = RegQueryValue(handle:key_h3, item:"FriendlyName");
              if(!isnull(value))
              {
                name = value[1];
                device += string("Device Name : ", name, "\n");
              }

	      value = RegQueryValue(handle:key_h3, item:"Class");
              if(!isnull(value))
              { 
                class = value[1];
	   	device += string("Class : ", class); 
	      }     	
 	      devices = make_list(devices,string(device,"\n")); 

              RegCloseKey(handle:key_h3); 
            }
          } 	
        }	
	      
        RegCloseKey(handle:key_h2) ;
      }
    }
  }
  RegCloseKey(handle:key_h) ;
}
RegCloseKey(handle:hklm);

NetUseDel(close:FALSE);

# Exit if we don't find any USB devices.

if(isnull(device)) 
{
  NetUseDel();
  exit(0);
}


path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
if(!path)
  path = "C:\\Windows";

share   = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

# Get the last connected times from setupapi.log/setupapi.dev.log
#
# For Vista and later, setupapi.log can be found under
# c:\Windows\inf\setupapi.dev.log
#
# http://msdn.microsoft.com/en-us/library/aa477110.aspx

if(vista_or_later)
  logfile = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\inf\setupapi.dev.log", string:path);
else
  logfile = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\setupapi.log", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

hash = make_array();

fh = CreateFile(
    file               : logfile,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );

if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize > 0)
  {
    # Read the entire file only if thorough_tests is enabled.	
    chunks = int(fsize/10240);
    if(!thorough_tests && chunks > 10 ) chunks = 10;

    offset = 0;
    count = 0;
    # Read the file in chunks 	
    while (count < chunks && offset < fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:offset);
      lines = split(data, sep:'\r\n', keep:FALSE);
      foreach line (lines)
      {
        if(vista_or_later)
        {
          # We first get the id first and then the time.
     
          if (ereg(pattern:">>> *\[Device Install \(Hardware initiated\) - USBSTOR\\",string:line))
          {
            match = eregmatch(pattern:">>> *\[Device Install \(Hardware initiated\) - USBSTOR\\(.+)\]",string:line);
            if(!isnull(match[1]))
            {
              hid = tolower(match[1]);
              flag = 1;
            }
          }
          if(flag && ereg(pattern:">>>  Section start [0-9]+/[0-9]+/[0-9]+ [0-9]+:[0-9]+:[0-9]+\.[0-9]+$",string:line))
          {
            match = eregmatch(pattern:">>>  Section start ([0-9]+/[0-9]+/[0-9]+ [0-9]+:[0-9]+:[0-9]+\.[0-9]+)$",string:line);
            hash[hid] = match[1];
            flag = 0;
          }
        }
       else
       {
         if (ereg(pattern:"Driver Install",string:line))
         {
           time = NULL;
  	   match = eregmatch(pattern:"^\[([0-9]+/[0-9]+/[0-9]+ [0-9]+:[0-9]+:[0-9]+) [0-9]+.[0-9]+ Driver Install\]$",string:line);
           if(!isnull(match[1]))
           {
             time = match[1];
             flag = 1;
           }
          }
         if (flag && ereg(pattern:"Searching for hardware ID\(s\): usb",string:line))
         {
           hid = NULL;
           hid = ereg_replace(pattern:"#.+ Searching for hardware ID\(s\): (.+)$",string:line,replace:"\1");
	   hid = str_replace(string:hid,find:",",replace:".");
           hash[hid] = time;
           flag = 0;
         }
        }
      }
      offset += 10240;
      count++;	
    }
  }
  CloseFile(handle:fh);
}

NetUseDel();

# Now Report.

report = NULL;
if (!isnull(devices))
{
  for (i = 0 ; i < max_index(devices); i++)	
  { 	
    d = devices[i];	
    found = 0;

    foreach k (keys(hash)) 
    { 
      if ( k >< d)
      {   	
        found = 1;  	
        # Get rid of hardware id, as it makes report clumsier
        d = ereg_replace(pattern:"HardwareID.+##(.+)",string:d, replace:"\1"); 	
        d = string(d,"First used : ", hash[k],"\n");
  	report += d;
      }
    } 		
    if (!found)
    {
      # Get rid of hardware id, as it makes report clumsier
      d = ereg_replace(pattern:"HardwareID.+##(.+)",string:d, replace:"\1"); 	
      d = string(d,"First used : unknown","\n");
      report += d;
    }
  }
}

if(!isnull(report)) 
{
  report = string(
    "\n",
    "Here's a list of USB devices that have been connected to remote system\n",
    "at least once in the past :\n",
    "\n",
    report,"\n"
  );

  if (!thorough_tests)
    report = string(
      report,
      "(Note that for a complete listing of 'First used' times you should run\n",
      "this test with the option 'thorough_tests' enabled)\n"
    );	
  security_note(port:port, extra:report);
}
