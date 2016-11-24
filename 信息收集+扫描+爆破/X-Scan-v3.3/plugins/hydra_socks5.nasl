#TRUSTED 3f312fdddae348a296bee6135192df9fb082e0d6035c3019fd8f85a26ee8c5a12b2b76a05dcd4a84322b5f56195beb616d1163e846b44bdf24635b0c4d0f448adecc696c8679cc04b074140bb0d915d4b9019e686b216672c0a929569404d5361dacf4cb11b83ad02a88950fe586b5017f95cbba18a1eeb87f3ec845c12a5a4fdb25022ca083f7cc32fc2fbd9cccc510b7b699d3c4c1d37f6069a3d35278f60e9ce1a7ff9bb1f6a505bda6518dbee8925cec352fd6705458b4cb9241d1ec28701ec367d289fed2be2fcdb4e10e163299ae48dc55879da1963c37e82df9a1ea47001dc7a12740b94190c4a500b4c56ab080525d12e961765007a68e7b2e862d6c452817e5363621ec32dc4ebf14afd5dbd2dacc47ec1d6260e3bac20578b4b41cb56443a0d7bb33fc43e5bcdd6f6ce4f5242892596e2dd4636bdaf88e9bf78f623c5a67f36cd96097c6f6e7763ecae7a5db7309f604ae82380fa0fb7f9cb8395f8e837783b69c9397e903b53614b6f25e56dd17b2f8b3283756cb58befb3137c38a0bd70468c86c5c6b404a75ad6a368782ab234040802aedd7703bb593fe16aef50cca58946425637f30f47e209bc418867efc6b9a6825ea266bf15182ece466e822d64bfaf16ac4c08493b9f3327c7220e06c9b742f58ae5365f082c6916c8acee1e45058a1ede0cd4060b49e0fb3d4242ef427cdf320bece18c0f599525bf5
#
# (C) Tenable Network Security, Inc.
#

# No use to run this one if the other plugins cannot run!
if ( ! defined_func("script_get_preference_file_location")) exit(0);
if ( ! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15887);
 script_version ("1.5");

 script_name(english:"Hydra: Socks5");
 script_summary(english:"Brute force Socks5 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Socks5 passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Socks5 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/socks5", 1080);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "socks.nasl");
 exit(0);
}

#
force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
}

logins = get_kb_item("Secret/hydra/logins_file");
if (logins == NULL) exit(0);

port = get_kb_item("Services/socks5");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

auth = get_kb_item("socks5/auth/"+port);
if (!auth) exit(0);	# Not authentication is required

# TBD: check that the SOCKS server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd != NULL)
{
 argv[i++] = "-P"; argv[i++] = passwd;
}
else if (!s)
 exit(0);

if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "socks5";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/socks5/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following accounts on the Socks5 server :\n\n' + report);
