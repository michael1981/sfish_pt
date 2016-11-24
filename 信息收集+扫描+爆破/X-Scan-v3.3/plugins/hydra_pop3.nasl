#TRUSTED 254458e9c658f2e3a3c4de18fe523613c40c7e29265e70e570380e25ddabc1504627e18d13175e4d99ebefb1a69fbc47a3bb789d5fb3f1549d7598f20899db728ea152e35610082ae406085266088c1b3737c777600852288fd20fc736b8ccc6f22c973ca967fbefc2119bae139de7dd41aae601c7d10b782b0daca5a42066ed6f9a02e501262364bde89ee41e49b1887f77bd6a7b92c8453b72c55d57bf32d9abe2be41cab40a0e8cc723c391ad1ed49cf6f78a16da1fb73080a964e1c40cc78972a91cb007120f1d94933d8e8bf9a10a3e8c6fc90e6f318fa75acb4218d29ed7f1b345c1319902063e46382de4134c5aa09b37a489deae8732f1a13d85c0b311b05e6af8b2d91c43245dc3e6e6dac8026f2d3df319533d625c3756e4f372cbb55a09215d613f497c8efc66b4b9393612065cb66e61ab20d88caac2a7b373337918b59cbe6067202d3c22f0ea5b0188c2615b6c19ed84f449cd3ea0224e5d846da625e7930fc1b387b975e3de4f524a88c0cde4e480781b9ebed9c4e1ebab44ad8c8a8cc7a9eeb1b9405169c15162e956477994101268961d37f9774fe1a88a0a7315f74d65a47b2b9d5f4c5dc12feb2879080acb4a162586b1a5090f540f01aea67d3804e9290fbf27433a3dec197c12b0dd7c804a789dda25589edab11fab6691319f47e762b35c707d449ab43be634bda92e279077e4df80dfb82e9332e3
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15881);
 script_version ("1.6");

 script_name(english:"Hydra: POP3");
 script_summary(english:"Brute force POP3 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine POP3 passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find POP3 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/pop3", 110);
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

port = get_kb_item("Services/pop3");
if (! port) exit(0);	# port = 110;
if (! get_port_state(port)) exit(0);

# Check that the POP server is up & running
soc = open_sock_tcp(port);
if (! soc) exit(0);
line = recv_line(socket: soc, length: 4096);
close(soc);
if (line !~ "^\+OK ") exit(0);

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
argv[i++] = "pop3";

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
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following POP3 accounts :\n\n' + report);
