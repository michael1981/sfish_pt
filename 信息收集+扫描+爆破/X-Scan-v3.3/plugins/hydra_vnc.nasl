#TRUSTED 0f59e8b662b78f7c13d7a40ca8de6dcffa6a1dcead776e21d9a11063722bf61e9d6263dd8157abe76696b3714f4614ccb51ef574fc4a4e19d43fcf1a0f16375b3ab07ec1bb06a7d309315c18d66fe709f046457ec360cafcac2e1189e7763757d9f8649fc941fdfd0e488e14719ee2b6388ab6cccf61ea9c8e9aab1a20c81eefe9e9314aeed64bcd92be0f048156feb3c1eb6eabd84058283aeb3e60c30ae0c108bd2e2788234d6e30f02c97bb719c8239a35fadeb693360cb0d1fbcfba9a7202c1f9a901f90e814950088998037048b752c3b822d0eaa8cdff939bb9cdf5d2fd534f5fd043c71a7e8cd648402ebf9af0ea195f51383bd3f244f6e89bd63744fdb1a3b976cc5e00ce09e2acaff0d9d372ffa05db65387aa265cc61625dbebf168b63942727224df70fdf3c442c999bacdec990f510c38afef4274e33b74ccdd9f74e91045260b42ed0e9937f80d21d700b2fc546fb755766df88c92d8f2474cd705194f1386448c9dd09ab07d174b9df2d4958a4ea2e2ec1ee0d7ca0bc236b72a47a46a6d1d5bc0ba0542e59c41d2cec2b11ee77e53150ef453d0345d58c162723de57789c19e528b05fa11147e9bf0dd797f3f01ed4ea7a0af6ea89cdc97075c19b5b3c9db33af21de58465659eafc15d50f8a91bd1bb2549e24fb3fae2251331c68e1ccb84c129aa4a18fbd272a98b7f774296d5916940dabb3ae93cdd5168
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15890);
 script_version ("1.5");

 script_name(english:"Hydra: VNC");
 script_summary(english:"Brute force VNC authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine VNC passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find VNC passwords by brute force. 

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
 script_require_keys("Secret/hydra/passwords_file");
 script_require_ports("Services/vnc", 5900);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "vnc_security_types.nasl");
 exit(0);
}

#

force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
 thorough = get_kb_item("global_settings/thorough_tests");
 if ("yes" >!< thorough) exit(0);
}

port = get_kb_item("Services/vnc");
if (! port) exit(0); # port = 5900;
if (! get_port_state(port)) exit(0);

st = get_kb_item('VNC/SecurityType/'+port);
if (st == 1) exit(0);	# No auth

# Check that the VNC server is up and running
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 512, min: 12);
close(soc);
if (strlen(r) < 12) exit(0);
v = eregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
if (isnull(v)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
s = "";
if (empty) s = "n";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd != NULL)
{
 argv[i++] = "-P"; argv[i++] = passwd;
} else if (!s)
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
argv[i++] = "vnc";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/vnc/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to find the following VNC passwords :\n\n' + report);
