#TRUSTED 0deccf33beaa47f50e96e10b44bc2f88e0680e2ba029f24fbd16cd6220650988e4acc20ddf1f859e12530649b6ff10bfab92fe032039ad322155a9ea15439e26958954af46feb865e5831e4455a44256190cfdc345a6a6a8b49e8af6c91847f0bcb7f5d84bf03762bdf18727597aaf817b32087472db5dae214f6562bf0ef3c36bb8b90fd05967d2ebe0d95983cf12eb5822805db40b6823011259acc6a348b8a9e313adb146d266f0853ce55476401d40b3412b4d1f352daf63f4aece6c5063cc15dcc86166f6e1b868e94e25dc78739a8e54bdc2153e056826d4479c1e206551668291c22078b8b17e14bdce378977ef183e38a4bd4944fb32a1b7c815ccb0672858659dd980a87720a534914ffda0be918e24c3b623fbbd490900b2918203f9efcfeb119a630e7f69a65cf20e551653e745ec72d7a5d60128070cfbb211771653595048a6dd7256312886562b510b8863b04d8a9907ebd26afa9357029ce380f303c664ddc0aa9b06fc8311bc3437b05df2e44eef1d1898d5de17b9ff6fe7521dea49128e9023b27c0335c9159b6c5e27fe21f388574d3f32867c5d3d8cf0c81b146c445451f0414c444bcd9a0980314243d64a09bbeb7c49e14337409f9da6229e7d0baffad71eb1e7eb5be7e8dd398b66c6676f916acadc36c82b6dcd460264268e3a6c5f01281cc7f23bc0bb5d6144857d69b13b91425eb1697b47a4fb
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(14273);
 script_version ("1.17");
 name["english"] = "SSH settings";
 script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:"This script configures the SSH subsystem");
 script_set_attribute(attribute:"description", value:"This script initializes the SSH credentials as set by the user.
To set the credentials, edit your scan policy and go to the section 'Credentials'.");
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 summary["english"] = "set SSH keys & user name to perform local security checks";
 script_summary(english:summary["english"]);
 script_copyright(english:"Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_category(ACT_INIT);
 if (defined_func("bn_random"))
 {
   script_add_preference(name:"SSH user name : ",
                       type:"entry",
                       value:"root");
   script_add_preference(name:"SSH password (unsafe!) : ",
                       type:"password",
                       value:"");
   script_add_preference(name:"SSH public key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"SSH private key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Passphrase for SSH key : ",
                       type:"password",
                       value:"");
  script_add_preference(name:"Elevate privileges with : ",
                       type:"radio",
                       value:"Nothing;sudo;su");
  script_add_preference(name:"su/sudo password : ",
                       type:"password",
                       value:"");
  script_add_preference(name:"SSH known_hosts file : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Preferred SSH port : ",
                       type:"entry",
                       value:"22");
  script_add_preference(name:"Client version : ",
                       type:"entry",
                       value:"OpenSSH_5.0");
 }

 exit(0);
}

include("ssh_func.inc");
account     = script_get_preference("SSH user name : ");
password    = script_get_preference("SSH password (unsafe!) : ");
public_key  = script_get_preference_file_content("SSH public key to use : ");
private_key = script_get_preference_file_content("SSH private key to use : ");
passphrase  = script_get_preference("Passphrase for SSH key : ");
client_ver  = script_get_preference("Client version : ");
sudo        = script_get_preference("Elevate privileges with : ");
if ( sudo == "sudo" )
	set_kb_item(name:"Secret/SSH/sudo", value:SU_SUDO);
else if ( sudo == "su" )
	set_kb_item(name:"Secret/SSH/sudo", value:SU_SU);


pref_port = script_get_preference("Preferred SSH port : ");
if ( pref_port && int(pref_port) )
{
 set_kb_item(name:"Secret/SSH/PreferredPort", value:int(pref_port));
}

sudo_password = script_get_preference("su/sudo password : ");
if ( sudo_password ) set_kb_item(name:"Secret/SSH/sudo-password", value:sudo_password);

if ( account ) set_kb_item(name:"Secret/SSH/login", value:account);
if (password) set_kb_item(name:"Secret/SSH/password", value:password);
if (public_key) set_kb_item(name:"Secret/SSH/publickey", value:public_key);
if (private_key) set_kb_item(name:"Secret/SSH/privatekey", value:hexstr(private_key));
if (passphrase) set_kb_item(name:"Secret/SSH/passphrase", value:passphrase);
if (client_ver) set_kb_item(name:"SSH/clientver", value:client_ver);


known_hosts = script_get_preference_file_content("SSH known_hosts file : ");
if ( ! isnull(known_hosts) )
{
 lines = split(known_hosts, keep:FALSE);
 foreach line ( lines ) 
 {
   data = split(line, sep:' ', keep:FALSE);
   if ( max_index(data) == 3 )
   {
    hostname = data[0]; 
    type = data[1]; 
    key = data[2];
    if ( "," >!< hostname )
    {
     if ( hostname == get_host_ip() || hostname == get_host_name() )
	  replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
    }
    else
    {
      hn = ereg_replace(pattern:"^([^,]*),.*", string:hostname, replace:"\1");
      ip = ereg_replace(pattern:"^[^,]*,(.*)", string:hostname, replace:"\1");
      if ( ip == get_host_ip() && hn == get_host_name() )
      {
	  replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
      }
    }
   }
   else if (max_index(data) == 4)
   {
    hostname = data[0]; 
    e = data[2]; 
    n = data[3];
    if ( hostname == get_host_ip() || hostname == get_host_name() )
    {
	  replace_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:string(e,"|",n));
    }
   }
 } 

 if ( ! get_kb_item("SSH/KnownFingerprint/ssh-rsa1") )
	set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:"QE5PVFNFVEA=");

 if ( ! get_kb_item("SSH/KnownFingerprint/ssh-rsa") )
	set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa", value:"QE5PVFNFVEA=");

 if ( ! get_kb_item("SSH/KnownFingerprint/ssh-dss") )
	set_kb_item(name:"SSH/KnownFingerprint/ssh-dss", value:"QE5PVFNFVEA=");
}



