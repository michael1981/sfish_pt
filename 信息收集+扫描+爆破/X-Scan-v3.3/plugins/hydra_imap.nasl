#TRUSTED 405403781582ece498076bd4ddb23d30b00bb21b1dec46a7afe336e5349ab5f95cd150e7eee0683f94ccebc04b45f76d9baf3ba857dfa127f9fe308a7ff5d5996c63e53534e7ece2302b7a6db1466c541f0beb01c032d65d4c1958805a4055185cab3bee826c2dba46d04d47b930faf2c19759bf7f9e8cb6d07c16e82a2084840285b8c5ee6fe833d85181c6936a6626021caa6586258b7da14b01d0d55a285004c27894461b75b57432fb859195ad25c6c96d4bd34a145c3017462940d8041bd88d9cd7af2e88b5ae053f54c2bf101c9b6b99d4630cce4c2ebff5fd9b97128d9b920c5064aeeed2f190d00471be221fa8ee124fe5b7d3e8dfbe3e417ecf6843451d2c2944996b51ebf9282ab4f21fb93d438c48aec13c26c17dda03435a6f1834066048814c5009161eb3c441f852a179da44048a2d548afef7d6cc4a0d7b01d9a3565bd52b37c02c0365fd03279702e80bbaf94b5572ef90a3cbc9821a6e6888e18ed703065edbd51f71ac974da1799cf0cd860adb5e5750eb989be1ab8cfaed7e6177a497fcee81b965a2bf96d0933573247c3f5b63ea7c9d101d3a5ef16cc7eeeb2cd42dd1e07dbe8af64dceca94ce45c5b4b6f0729d3de023bade0d12c719be47d1d74385ee363510f8a0cb90e7295e57c28fe76cf9d960fae35df493b90292717457b578bb8621cc9d80078e11262f055c430dc497d2a8367a3cb0eeba
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15876);
 script_version ("1.5");

 script_name(english:"Hydra: IMAP");
 script_summary(english:"Brute force IMAP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine IMAP passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find IMAP accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/imap", 143);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
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

port = get_kb_item("Services/imap");
if (! port) exit(0);	# port = 143;
if (! get_port_state(port)) exit(0);

# Check that the server is up & running
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 1024);
close(soc);
if (r !~ '^\\* *OK ') exit(0);

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
if (passwd)
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
argv[i++] = "imap";

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
    set_kb_item(name: 'Hydra/imap/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following IMAP accounts :\n\n' + report);
