#TRUSTED 63d67c9925fcf4789beb49d5f9a62fc5648dd34b6b44d2b98f26c341b6b0a936909d5e03fe20258be2c8c9240c01c468c7a388ec09802622342dc682c0860821a319b0b0d65edebfd7da5821cf9c70f2f68cb203e6429365fe80ed076a3800ab5eaa7121757958904b2c19ad678fc62d485f07e0e2d7408bcd5c06abbd1b08b24c50be30d5cdc64f80461eda3f98cdc72cc698f7647aee9eb0b34079d53acc8f5ecb28b77871f8445539425270c0f429ee7bdce3879bf99dbbe67bc0ebd2cdead45a6a92d5040d6576ed50ef8467f6ecf0b699b8bc2bfb3e4d60d3ad5a0378423c830817634c3676dbd956b996161c750dd71b628901507759fec833e3567ff80b1fe4908036f7fcd8ecf29429c7c756315e40bd6e2c1c0ecb85f1c89d29e929009a01ed30e5b8c1372396e063fa52ac8c06c1a15ef2b9f1126502475dce62397622543eddfb31e17f363af1ae4df9952e40e5c2cd7532ae0e8b965895e207de09f6eebf7f279268b468f8960d1cef8d79aa9cce9c098ef5d3cd1933a840256dc200d8434475cd77bf77fb07e4468a49dce28f6878dab74fc96764bec9a05b82bda301c76cc1cecbd0c928bf2473c0ca85942d8f53440abda6d382d87b25e48f611bf62615ad198b26057911d86035742f2dbbd66bd9d380921301d0d1d69c4092a39e208c40efdac0555e44778db61ea323e6a0215014a60a9deb43479f1265
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15882);
 script_version ("1.5");

 script_name(english:"Hydra: rexec");
 script_summary(english:"Brute force rexec authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine rexec passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find rexec accounts and passwords by brute
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
 script_require_ports("Services/rexecd", 512);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "rexecd.nasl");
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

port = get_kb_item("Services/rexecd");
if (! port) exit(0); # port = 512;
if (! get_port_state(port)) exit(0);

# TBD: check that the remote server is up & running

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
argv[i++] = "rexec";

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
    set_kb_item(name: 'Hydra/rexec/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following Rexec accounts :\n\n' + report);
