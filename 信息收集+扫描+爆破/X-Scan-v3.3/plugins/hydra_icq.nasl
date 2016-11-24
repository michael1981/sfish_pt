#TRUSTED 33ce18c7bf4494d8a9dd1ccd876d0dd21213d441d68a3e5e0156d62144a65a0e656461687765f0c962532a5d4e1916c9eff3b02f5d2d80228ffa62fed5d46af4fe2c6827dbea4746586e8922bccef436c17aa8d11b425591db09f9046ac7526617a28ac7624f1893bb31804668cfb34b6cce2e17f53eab8c78131240935108863d9cb89e5ff178f9aea369241810f1f49ac94a55d8e5bb1c474c5f28c9980347f3ede099c779a0f2f46f395aaacb6fc4cd8eddc6e78da152feab8c45f822494db41c6e90da28550ef0f4d4f1b84f4ab3cb5a895dee423c69a14df1bd8ce677fa90080b5a5c3d7fea713a320cd5ac6615ab25e0f993d5cc58e0473bd8542d1c0959fef4ed3ab982a4628b0830583b8cecdf68620f7aac295180f543dfa8b223296e5400000c4d8daff69d4d652304c7aa171945eb74de4daea73566275199fc650b5151d6caf0b666a2f3ec048b0fc01ec0b5e5de71aff68a2f997df1de864b69f531a6eab709a608f1719e822e9fd9d633eb234ba56ca013a695740e1ad0247a2092919aab59d12e7dfffa328f906d63998b3a00e88f1ea2c76ab0df46b1e8002ed8db09d8999a0cd8df3194333783f71988a8f36f7008a4bcbab8d0faa703b31c837ac275c21013a3738a13d234fd7c46f2411ebea3f5ff705408f649c664b7ccea0f69b08e6035764c04279f845f6565bf39ae2c9b2d01ec42b9fb039121cf
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15875);
 script_version ("1.5");

 script_name(english:"Hydra: ICQ");
 script_summary(english:"Brute force ICQ authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine ICQ accounts through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find ICQ accounts and passwords by brute
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
 script_require_ports("Services/icq", 5190);
 # Currently, ICQ is not identified by find*.nasl
 script_dependencies("hydra_options.nasl", "find_service2.nasl", "external_svc_ident.nasl");
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

port = get_kb_item("Services/icq");
if (! port) exit(0); # port = 5190;
if (! get_port_state(port)) exit(0);

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
argv[i++] = "icq";

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
    set_kb_item(name: 'Hydra/icq/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following ICQ accounts:\n\n' + report);
