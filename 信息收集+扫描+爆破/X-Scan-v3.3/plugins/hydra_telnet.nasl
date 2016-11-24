#TRUSTED 5bdf562e4a5a3aee1f16af2e48ab04bc2e75e757d2ac69edec3da951bbe4012acddd3f282842746ce2ba107ad9070afd7872f75b3b34b3cd7ffd910e0f7c28efe41fe20a38aeb921cf8f42229208784279d1a251e5908b79c3718e985546d0312efca949d0ca9675987454f64a97c2051b67f71dba18c5a2d529e4bfc6906dc8ef6a2e9f406f914f627e009404b6c8a9fdd7a0a54523839807de82d10f5af93d559cea79762a96dd2aec4609645ed3121bdcab205cfa7826c11282933a33e1bd327eafe6d78893594f533910fc867c36669770610dc27bda4a41e4362aefbb844056bc0623611477fa293487d297ebb6e97361cddb347e8032d7913731c0da70cf65a3529aa4a3eed9ce5e1362edb3de9909358430c048afcbb84ca0a646ef3554d8a1dabb83ff0bf6b89e83f211d9a50ece0315f44e39216995cd9d6d929ce3ec91f53e42579107cca1c5b98c9f4f1b8db31a6abf2d0ae36e1feb9731a0458e2ec2ad91fd6862832eadd2b3c5109c238511da1de8195bcc877ba73f78f3419edaed0bbd2b83e29610c6915339064c4ad4afea8f0179d35cc9ed97e16d48c9b0f3ee737f4131fc57cc5d16f897fcf28359badee29f94f61c4da4023cfb09f58265c708333c12413e9978b956dddef362225ef19ee78c0e30414395e21c340091ef8f3592dd76f7f3f3d26ecbe1339ebcc21525085fa058b641c566dca048ca4d
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15889);
 script_version ("1.5");

 script_name(english:"Hydra: telnet");
 script_summary(english:"Brute force telnet authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine telnet passwords through brute
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find telnet passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004-2009  Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/telnet", 23);
 script_dependencies("hydra_options.nasl", "doublecheck_std_services.nasl", "telnetserver_detect_type_nd_version.nasl");
 exit(0);
}

#
force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
thorough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< thorough) exit(0);
}

logins = get_kb_item("Secret/hydra/logins_file");
if (logins == NULL) exit(0);

port = get_kb_item("Services/telnet");
if (! port) exit(0);	# port = 23;
if (! get_port_state(port)) exit(0);

# Check that this is not a router
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >< r) exit(0);	# Probably a CISCO

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
} else if (! s)
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
argv[i++] = "telnet";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/telnet/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following Telnet accounts :\n\n' + report);
