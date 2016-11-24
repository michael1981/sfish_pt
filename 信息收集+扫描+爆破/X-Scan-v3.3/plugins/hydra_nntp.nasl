#TRUSTED 4f225bfdf5e686d50f8fa2d8e457108bab52c319bfbb46fb67e9fc72dd55f03ee4572bbcb777ace197134f4c876a641d6a6133d6c949d1c93fb80d2a78f8a58d31c8c2650a7ca3e7d706595041029eaceb1ea76f1cd84a258cac3d489274a97d8df5dc24c0a454c2b676cea8e38feb35abafcae21672c40259e51f6fb245675f6c1d32f969b0a985470d55396d047238c60d5820012e23a95d5bd04767259e1cb33d0767b6a8606c6ee965c24e54ab1c5ebb12deb096bdc518236bd3f9769ba8b180997f0d893cf3fdc663f6ea3564dfd5f9b0c155b3d5f7d9fe12ea0ae97dddd6439c095cb64ed5759873f53c960d9f1298eb7c9cf334e6d9ee2f754c1122aab291cf2e53bc4516d3e5eaaa362fcb26687df1c1e74e9ed78eab81b6f540b175902d1a8267f4ca0c61beca35a772bd87a26b93b5dc8a385f885752692ac507f6dd21cc4de549e07de92e954ed2f76762e57449c9a63d05d84fdf4b0e98035277620ed57c9850ef5a3daf2fab33945df412ea7ef34147a54e1448f8326c7e5434f7b25f457f6f88c820873c208955dbd3d3c9a1222f7555fc0bf380f19dce797762bff71b3e8db8a65efc16fd87bb8faebd2a11c3f4cd841de5c4bacbecbf73fd62c1d23035c5e8936a28a96c0e76bf71ff6edd735c605ff99d141d43dcbc743ee33a3d1a312de1cae424ee9fd1d0249a4a7cc0c4a0b03020be5557264498be1a
#
# (C) Tenable Network Security, Inc.
#

# No use to run this one if the other plugins cannot run!
if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15879);
 script_version ("1.5");

 script_name(english:"Hydra: NNTP");
 script_summary(english:"Brute force NNTP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine NNTP passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find NNTP accounts and passwords by brute
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
 script_require_ports("Services/nntp", 119);
 script_dependencies("hydra_options.nasl", "nntpserver_detect.nasl");
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

port = get_kb_item("Services/nntp");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

# Check that the NNTP server is up & running
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9] ') exit(0);

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
argv[i++] = "nntp";

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
    set_kb_item(name: 'Hydra/nntp/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following NNTP accounts :\n\n' + report);
