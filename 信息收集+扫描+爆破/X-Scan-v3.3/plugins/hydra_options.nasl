#TRUSTED 5c40ff6cd6540e6cf2b8884bd67dca49a701e786b1bbbed3e546c6e0f9c7dc4c55b005a2574ba91a3b36550789b6f076dc511d7857ee6d18e9ad2077cacbc1a8fcb21bb010b17f0ee7733632d4d3e48fa6bb2a9f4f381d304e172319e3e3178a716e58c373e656994b77af025135ec6031c61b8670da0b4725f82743d2b42f3c2d3b66d11af7f94bfabbbbaa9e2cc8b205b0dd59d023745942bf8e3fb51562fc6cf449200a532a13c0a911b456d6ead15b09a5a04e02edd93b651422ff44c10d70941eeb2eea448a076a2f9a789cd1ad1bbd41598b5d50f1c336c22d48600a20bb96b942154e8887b37a7b7bf0974e4fb41391f9d959f64fd448bd7385480147abc23a4b5ec0f904224fa8a0bcdd3969acdf7d98db25cdfb6febfbc54bd55c4b3f21ef9f9d2ea29b6b9d5cdf7060adce3e28cc2a928171de518ed0af2dbb98864cb32230d663cd776d478185f481c7b3064b666c264b9131dc050b3ab3c2178c75531d65e3c9b45a7958c7c8ffb3f4e261ae1bc4e247428b11dbccf142b44251b606346f4657e8395c30bd932443648af37cc11d6f8976de13b0fa6653aa769bff4d6f7cf8ea01e08185f9ec0a990ae3478d9af74235d004328b9543d584586902c651218377365729c45d93814274ecb2bd20b152b14737db42697845b17c0441bdf3a2e904069fe76e9aa12cc3dce76386a0024a5ab4e79ca2fe11d38188f3
#
# (C) Tenable Network Security, Inc.
#

# No use to run this one if the other plugins cannot run!
if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15868);
 script_version ("1.9");

 script_name(english:"Hydra (NASL wrappers options)");
 script_summary(english:"Brute force authentication protocols");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin is used to set options for Hydra." );
 script_set_attribute(attribute:"description", value:
"This plugin sets options for the hydra(1) tests.  Hydra finds
passwords by brute force. 

To use the Hydra plugins, enter the 'Logins file' and the 'Passwords
file under the 'Hydra (NASL wrappers options)' advanced settings
block.");
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_end_attributes();
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_add_preference(name: "Always enable Hydra (slow)", type:"checkbox", value: "no");
 script_add_preference(name: "Logins file : ", value: "", type: "file");
 script_add_preference(name: "Passwords file : ", value: "", type: "file");
 script_add_preference(name: "Number of parallel tasks :", value: "16", type: "entry");
 script_add_preference(name: "Timeout (in seconds) :", value: "30", type: "entry");
 script_add_preference(name: "Try empty passwords", type:"checkbox", value: "yes");
 script_add_preference(name: "Try login as password", type:"checkbox", value: "yes");
 script_add_preference(name: "Exit as soon as an account is found", type:"checkbox", value: "no");
 script_add_preference(name: "Add accounts found by other plugins to login file", type:"checkbox", value: "yes");

 exit(0);
}

#

function mk_login_file(logins)
{
  local_var	tmp1,tmp2, dir, list, i, u;
  if ( NASL_LEVEL < 2201 ) return logins; # fwrite broken
  dir = get_tmp_dir();
  if (! dir) return logins;	# Abnormal condition
  for (i = 1; TRUE; i ++)
  {
    u = get_kb_item("SMB/Users/"+i);
    if (! u) break;
    list = strcat(list, u, '\n');
  }
# Add here results from other plugins
  if (! list) return logins;
  tmp1 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  tmp2 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  if (fwrite(data: list, file: tmp1) <= 0)	# File creation failed
    return logins;
  if (! logins) return tmp1;
  pread(cmd: "sort", argv: make_list("sort", "-u", tmp1, logins, "-o", tmp2));
  unlink(tmp1);
  return tmp2;
}


if ( ! script_get_preference("Passwords file : ") ) exit(0);
p = script_get_preference_file_location("Passwords file : ");
if (!p ) exit(0);
set_kb_item(name: "Secret/hydra/passwords_file", value: p);

# No login file is necessary for SNMP, VNC and Cisco; and a login file 
# may be made from other plugins results. So we do not exit if this
# option is void.
a = script_get_preference("Add accounts found by other plugins to login file");
if ( ! script_get_preference("Logins file : ") ) exit(0);
p = script_get_preference_file_location("Logins file : ");
if ("no" >!< a) p = mk_login_file(logins: p);
set_kb_item(name: "Secret/hydra/logins_file", value: p);

p = script_get_preference("Timeout (in seconds) :");
t = int(p);
if (t <= 0) t = 30;
set_kb_item(name: "/tmp/hydra/timeout", value: t);

p = script_get_preference("Number of parallel tasks :");
t = int(p);
if (t <= 0) t = 16;
set_kb_item(name: "/tmp/hydra/tasks", value: t);

p = script_get_preference("Try empty passwords");
if ( "yes" >< p ) 
  set_kb_item(name: "/tmp/hydra/empty_password", value: TRUE);

p = script_get_preference("Try login as password");
if ( "yes" >< p ) 
 set_kb_item(name: "/tmp/hydra/login_password", value: TRUE);

p = script_get_preference("Exit as soon as an account is found");
if ( "yes" >< p ) 
 set_kb_item(name: "/tmp/hydra/exit_ASAP", value: TRUE);

p = script_get_preference("Always enable Hydra (slow)");
if ("yes" >< p)
 set_kb_item(name: "/tmp/hydra/force_run", value: TRUE);
