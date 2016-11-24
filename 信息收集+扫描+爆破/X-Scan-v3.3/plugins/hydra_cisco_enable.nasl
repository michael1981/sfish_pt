#TRUSTED 2e738e99bf065476feb348b534f2912d44e37a40e888ee0200124b2d47a731c8220146231dbc378d7940dee91808d5d81b1b0ab4a12b00d0792c6a6cb0ba3e454a4b7250bbdc6f754f0cbce7cabccb8b7b553d59502e5b39d9c7a85bc518fe7124085656c0e5b637ffb538d2d196f377cc596fb95cf828b056f5f0ad55880e13fdc60b3bb616eb6de62767c16a60c7e94c17f35530a3d75bb99932558fab650734470a6ea2f4ecbb85efc24e5a278f0602e92b08fb89742432ae6f460f62a65d5302c7494018a2af391f472070a7be3f1ae50e468e0d49f1c92fd4976a8929a46cd056f4ac9462a36c859e6c57ecd07c9cf7f1cab8118f2ddd22973236aad2003b1a89239ae2674cf37cb2ed208b7b1fec880deea1d346830d16f141bf9685bc4128104fbc6e782ecdcd03aca1256fe95c4a67be0ec2bbe2819e016deed79616b966da5d25320e601dbfea7aef5d33149116cba47a8a07eba44f6a9079037b1bfc8826a1914108f71b7775809d3246de032f30fb6f0cd16ba625e93df641b93544243772ebea7f2f8ee15b2b107a2c02133ce8e10bd8812e58aa32e67ad369b708fb361a4fe69445d02c488c049e63ba314aba417caacce091f2f96c9253bbce6ca3ba3e71ba3a9a4f1e03081a66978522370ff9238ef2e63f4c30d4510bdcaa34179fb42cb33283d8f81190952cb7d1e5a6ffb239d7e4daaa97d39f27bea478
#
# (C) Tenable Network Security, Inc. 
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15870);
 script_version ("1.5");

 script_name(english:"Hydra: Cisco enable");
 script_summary(english:"Brute force 'Cisco enable' authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Cisco passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Cisco 'enable' passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_add_preference(name: "Logon password : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_timeout(0);
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/passwords_file");
 script_require_ports("Services/telnet", 23);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "hydra_cisco.nasl");
 exit(0);
}

#
force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
}

port = get_kb_item("Services/telnet");
if (! port) exit(0);	# port = 23;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0);

# Logon password is required
pass = script_get_preference("Logon password : ");
if (! pass)
{
 l = get_kb_list("Hydra/cisco/"+port);
 if (isnull(l)) exit(0);
 foreach pass (l)
   if (! pass)
    break;
 if (! pass) exit(0);
}

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;

if (empty)
{
  argv[i++] = "-e"; argv[i++] = "n";
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
argv[i++] = "cisco-enable";
argv[i++] = pass;

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    # l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: "Hydra/cisco-enable/"+port, value: p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to find the following Cisco enable passwords :\n\n' + report);
