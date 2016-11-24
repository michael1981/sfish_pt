#TRUSTED 6fb8e6897ec33d1d47c7d81b6a2809426e3f073aa62017da47ea4c4d1ac780b2c2bdbe23a4ff44c89d87c119ba3bc9abfdd0e6904272ed05b461ac3cb95b61dbdc14709b16afd463dfe6c6c498c0c381367e0fad2f8f452f4e4a4c934f2483ae78c539e727cda09da545bef2da831e3345d90fd2acfcd4d909cbcb50478700b1c79df6e6d150d20e4a2d2272a4e07bdb86256db0500cb4d68535864f825e21b71c529847a8af63e979f418e375ff865ace0d8712bd3701d1df197256ce01a339c113bec2e228efe434ea86cccead16d4e15c26c11111e9a8d83ea74a279a09848ffa5747d462612ec7c806835c31137d1e5df287ab941e24a3b2eb40960853f861ce027741a1f0490206ad1b64af45488fb5f740c2e8e558e2a375f50ee9c2fe06fcdf82f020c7aa6c75f5c8802ac2c688be357a5a48b099af09f32b92a3b6d3090150966fb790ec7d9cfdf78eb23fb69b9d8868ed16f97eb2648211f53570179c92d863376efcddc9d28a29b243543a022601fcc32560a757f0f8d4c41d803d9ebbd826f147a7f1022b3c1b1e8c4c2e54b2bc5f0fef6c81f89b9d9fccf065dc82748aa0555482331c16e5b67d976ff84531402683a5e49c959de18219508d6591706b2604168a216b389a94360dcfd06b98fddaa6307cb78bacee4eb9e80b7e2899bbb6f4760376f5750d70199922e3fca46787bd48ae37d7137c18ace157a4
#
# (C) Tenable Network Security, Inc.
#
# @@NOTE: The output of this plugin should not be changed
# 
#
#


include("compat.inc");

if(description)
{
 script_id(10267);
 script_version ("2.3");
 
 script_name(english:"SSH Server Type and Version Information");
 
 script_set_attribute(attribute:"synopsis", value:
"An SSH server is listening on this port." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain information about the remote SSH
server by sending an empty authentication request." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 script_summary(english:"SSH Server type and version");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_require_ports("Services/ssh", 22);
 script_dependencies("find_service1.nasl", "find_service2.nasl", "external_svc_ident.nasl");
 exit(0);
}


#
# The script code starts here
#
global_var debug_level;
include("misc_func.inc");
include("ssh_func.inc");

if (  get_kb_item("global_settings/supplied_logins_only") ) 
 supplied_logins_only = 1;
else
 supplied_logins_only = 0;

port = get_kb_item("Services/ssh");

if (!port) port = 22;
if (get_port_state(port))
{
 version = NULL;
 if ( defined_func("bn_random") && !supplied_logins_only ) 
 {
  _ssh_socket = open_sock_tcp(port);
  if ( ! _ssh_socket ) exit(0);
  login = kb_ssh_login();
  password = kb_ssh_password();
  pub = kb_ssh_publickey();
  priv = kb_ssh_privatekey();
  passphrase = kb_ssh_passphrase();
  nofingerprint = FALSE;
  if ( isnull(login) ) 
  {
    login = "n3ssus";
    password = "n3ssus";
    pub = NULL;
    priv = NULL;
    passphrase = NULL;
    nofingerprint = TRUE;
  }
 
  ssh_login (login:login, password:password, pub:pub, priv:priv, passphrase:passphrase, nofingerprint:nofingerprint);

 version = get_ssh_server_version ();
 banner = get_ssh_banner ();
 supported = get_ssh_supported_authentication ();
 key = get_server_public_key();
 close(_ssh_socket);
 }

 if ( isnull(version) )
 {
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);
 version = recv_line(socket:soc, length:4096);
 if ( !ereg(pattern:"^SSH-", string:version ) ) exit(0);
 close(soc);
 }

 if (version)
 {
   set_kb_item(name:"SSH/banner/" + port, value:version);
   text = "SSH version : " + version + '\n';

   if (supported)
   {
     set_kb_item(name:"SSH/supportedauth/" + port, value:supported);
     text += 'SSH supported authentication : ' + supported + '\n';
   }
   
   if (banner)
   {
     set_kb_item(name:"SSH/textbanner/" + port, value:banner);
     text += 'SSH banner : \n' + banner + '\n';
   }

   if (key)
   {
    fingerprint = hexstr(MD5(key));

    if ("ssh-rsa" >< key)
      set_kb_item(name:"SSH/Fingerprint/ssh-rsa", value:fingerprint);
    else if ("ssh-dss" >< key)
      set_kb_item(name:"SSH/Fingerprint/ssh-dss", value:fingerprint);
    
   }

   report = string ("\n", text);
   
   security_note(port:port, extra:report);
   register_service(port:port, proto: "ssh");   
 }
}
