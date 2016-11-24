#TRUSTED 646f58cf5d96badec56bda9f2e5a9a76ad06d936c295787da66f847f3f218e63c8ea32e4495e5fa5c1c25bc79030290749a9a53d1e161972c7ca6b3201f6206fd903309164a93f4a1301b525e79ebf4c5e9a4930893bbcaf35c1511a721857604fbed713d7a8b98dd266978b86b2693b34f157e5d948e10c2f7cf28b62ade846cdf2475c390ce58a9e64629adc70becf42049e83f6aea158338fbad0342b1dc1560b645a8d977bb844a973cb776faebef2ef5e45a8a8cedf859f45212c9cbd86cd8906b50d0e1eeb352a7185978abcc699361332f2a36cc2d2ad2417fd8b87c330e5866bdb35c19d7507f212db30b3c3cbd32aced04c8a9eff7790eead877e48d309548772cfaf032288657734ae977b19c937d5c8e9ca409510b994df5e898c5a1dbbcc188b92dc1923fee4e8e71407cdcaab0805eea472416ab4e7ef647686127910e6e079b2452a8a1dde607c5ff8800ba70510f590fc2cb723ecd9e4e5c221a330afbdc3fc7035465fd14b8fd4f4c0ad5365a1a0dc6ed96d4c03553d56f39e45568582429be163f19a7297d2eab19a83dbcd0cf5bafba0ddbd2f667f520e475ebe6a9f949bea05dc2336f8556ce0c494cc4a346fc58fe81458557de207215decfc92e6bbfdb40605ada901a139e12b63c0eaa9d65ba19f6fd29c20857448373e58365ced49bfd3268c2449d20a22c4e34391a87d3ee28c714c7418553eb1
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15878);
 script_version ("1.5");

 script_name(english:"Hydra: MS SQL");
 script_summary(english:"Brute force MS SQL authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine MS SQL passwords through brute
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find MS SQL passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/mssql", 1433);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "mssqlserver_detect.nasl", "mssql_blank_password.nasl");
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

port = get_kb_item("Services/mssql");
if (! port) exit(0);	# port = 1433;
if (! get_port_state(port)) exit(0);
if (get_kb_item('MSSQL/blank_password/'+port)) exit(0);

# We should check that the server is up & running

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
argv[i++] = "mssql";

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
    set_kb_item(name: 'Hydra/mssql/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following MS SQL accounts :\n\n' + report);
