#TRUSTED 8b694753c4e4f984dac4caeb0227289f4b1d907f78c1abe73bf03504700b0ddc524b6b602279a8bc9dd7516773f6d83a94c233105162c7a05a549010fa48307d04d237b1e4428bc52f4cc2112529e3906daa97f27d13a128bd8500939c087e0e857d956fd7c6b38b3ac93446d36279f85cd79919c0014bfce957d284f1acb62ea19faeea608268115e44c7dec0bd33ab5f72a3a65f866c11a16ee6d5789ccf9e32084178518974d093511ef7a6d1c7072304cc455961059650f1bdf0c30d77867c984a4b77bb75d97ee00fde63290f88ad521e75feb71aa301a0aaa030c90f8ca70d188476c1a4bcf15e8040a845e1195b80c6a1906abe8dbb58e92657a3c509bf941ede40d79c6759217673fbd9adf48828d0ad4db8b9044a0e611eb89b13d5099b48db4f3569991612531aefe5224f79b0b132d669df73c080c04a71961cdbeffb8ce1807280b8fc0e88bcd8f820a3f51cff168afda813bef2cf6165ad3a57e544fb15d6448d628e4a6919090c4b4949ed24278d52a31d965312231f8d6476c119c483b58ebf3a3f1cbd8ed14ca8b79a453cdce5bb2dcf71321f9dc003be85776287f85e522654a5a201f63de61eed8f8fc1c9f15a03fba244b16a10927dddf46568f68be44dbe7dcf337de9a3bca95856e47f81255c7196e5500cc72a767ccd6516f6530f5a8821d964d9c0417232782557ec9e1653d2d2ff5677dafb7c76
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15888);
 script_version ("1.5");

 script_name(english:"Hydra: SSH2");
 script_summary(english:"Brute force SSH2 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SSH passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SSH2 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/ssh");
 script_dependencies("hydra_options.nasl", "doublecheck_std_services.nasl", "ssh_detect.nasl");
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

port = get_kb_item("Services/ssh");
if (! port) exit(0);	# port = 22;
if (! get_port_state(port)) exit(0);

# Check that the server is up & running
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^SSH-') exit(0);

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
argv[i++] = "ssh2";

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
    set_kb_item(name: 'Hydra/ssh2/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following SSH accounts :\n\n' + report);
