#TRUSTED ac231de9beabeb03c44a37bb01133b1d0d1b39b2cc61cb33a53743ff452035521131c6ecbf63d8ada480da0cf40818a9772015d516eef83177750f406a93f67cef1bdb6ac5292f0648b2b8ca36625154d5799eba17ce9534d1de61ecc647c95e4215a000dba56096ba3565275ed43592992e628d8f6cf74990d463eea6a74ce2def9a06ae8ed21a1106a7cc291f0e20e20edf8c497d49180ad0e0bcbab8e726f2401d87a3c3f7e9b5085b4786431e8b1d1c06e2dd1c63c445c474761a046145457a199f6b9adadd4b88dd8a1ffae6bc679ffa46451a43d93d4e7d92c9fc322fc75e77a14f352bed9a9febcb432c5e9444f84a05a30f07f5ba82d724c2a03c1eb16b40469ee98702e080ad9ded6faac474efdd07ee441d20466a603e171b9e67595f8e1c4c4b3cf85ec7d0f9e13705e9f7bd4cac824bebe909de7a1f317fa83a21a3165d21f2ea92a2223ea358f7249afa68c91d55260c482645b558c9d81c495df4eac4762acd5809f3f618f29126f18c6149def43e12040935a4a19035dbf6b9a6c437f017102516cb3f9069a9d47ac05afe0c59d1b04d1695dba9f420e1913c44aa08121cbafa98c91acff5e090e0d434c2350154f81e4c7d44ed2bfea6051fd9984fa705e50b540bed22de832d6bdc2cf7c93e3c49f6e199845d7f9560548dc9ae0e69d536a6fad0df1a6ae7c99b42c8a276fd2e0409ebeb449b1fb514cd4
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15872);
 script_version ("1.5");

 script_name(english:"Hydra: FTP");
 script_summary(english:"Brute force FTP authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine FTP passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find FTP accounts and passwords by brute
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
 script_require_ports("Services/ftp", 21);
 script_dependencies("hydra_options.nasl", "ftpserver_detect_type_nd_version.nasl");
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

port = get_kb_item("Services/ftp");
if (! port) exit(0); # port = 21;
if (! get_port_state(port)) exit(0);

# Check that the FTP server is still alive & answers quickly enough
soc = open_sock_tcp(port);
if (!soc) exit(0);
r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9][ -]') exit(0);

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
} else if (s)
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
argv[i++] = "ftp";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword:', p, '\n');
    set_kb_item(name: 'Hydra/ftp/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following FTP accounts :\n\n' + report);
