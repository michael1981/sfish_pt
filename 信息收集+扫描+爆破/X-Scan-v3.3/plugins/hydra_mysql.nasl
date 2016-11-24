#TRUSTED 4f7fd817e0f8658e863c48b4c646b60ceb90ad946f3b836318905d83c7db78fd515a137277575561726bd677c82844fcacc7d26887b37ac3709da5694ca337ffd1b8e9195c15ea7923c73dce2dd348d83f402abd9f59d937fe39f30a080d7dcd656a33b5b51bffc314086251d967b79052333a12f30a2a4061e96ae45eee76a0d173f69a4841d6dd1504fbd9a57ff90dd09519fa9db97925e97dcb4f2f36477188c16e4265f0bb12e2db67d8fbd8cee7ac3643187c0af13b377ddeb7d3719f95bbede764cec2d19331b22b68672e0ccbec39f1d20787da0ad35c85d9866934f399653feac90adb9d0903bac3b0786cb500348c0cf6c67a01478a2fe7f6904735376d98efdd68b5949750cdce9cffeb2ade19b60e220533f863d63e29bc469d52454bc53c9bf738d50309d6255bbfa8adcd97a676b705e62a86d998a7b0229b5d49f357f56aea0931ce5fe9b20fd410d2dc3810e10515252c605244bbb78643b08a35f06795708d90a280a28afd5aaa9899659a8085c1308f4af371951e110e793953779257fdd456002dfd8a0b1e14c895dfd1a935428735a41ee1689874961429347f322e773d95df6eb0d7c4328a2e2a6244fae0b77b2c9371c0fee67de8397f393f4ab2374b02dc317922a6132e327930f01a6f27854548bc02228ff6dee3162579702a0cad1e55bea525d3ef555bc8d12cf20fafc36c7b88cd1cce8be4a7
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(18661);
 script_version ("1.3");

 script_name(english:"Hydra: MySQL");
 script_summary(english:"Brute force MySQL authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine MySQL passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find MySQL accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/mysql", 3306);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "mysql_version.nasl", "mysql_unpassworded.nasl");
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

port = get_kb_item("Services/mysql");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

no_pass = get_kb_item('MySQL/no_passwd/'+port);
if (no_pass) exit(0);

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
argv[i++] = "mysql";

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
    set_kb_item(name: 'Hydra/mysql/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following accounts on the MySQL server :\n\n' + report);
