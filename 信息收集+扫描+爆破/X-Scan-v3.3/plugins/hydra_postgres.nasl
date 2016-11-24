#TRUSTED a7006ff0c9de181f70b3df811dc4a511f3545fe6758610b74829ade1d42e006068a824f6511edb230f387a3049ae0f603498ee9dd1575b13879c4810264bae62b0f2ed6d3c3de2201d64e11071268c261189376ddd5898bb74afbd55a7ccb06ec7eab8e3bfb3936775a5d917d4015f8f50738b449e68f4967888471fae1d6af89388705f90c16a154d9cb4c04473a1bdc0d57228d26c3a415b6372c10ce839fe5ebb6b8d4964da9c3735b353a08b2de1057d958275adc27255468a50722cffadb08a2c587afa10bb419a92080ab0313eec977c4b3aecad8faf94b75f0c92da806cb1c80352714614bb1a075a2d6447828228cf6ecbeec553264e3ffb65c0d7d1a31b879d708bf8196a523aff12dcc4a4e5747e63d652bb261466cb6508dc826c564ee37de8825a975e9bcd1165de49ae637672f2e08bdea4791f734e13dfa0c004b014d0bc792765cc2e95f1e58449b7e02a83e8eeec1b012e2392b58611ee9418c5455208729afeea4d76d1d01c9d499e5fc61c163b15103211d194df15727fd9aa8b5dbf33705b8475c8682e669ba6a6ac5ecb894c4af86a252c74d59ad15dda2b90e85e01c0e448c545b91d347722533c54e1e41d6cc96d3ce42e141f37ab80aea6891cd1ddb9deb978fe2e13ab6ce7aced0959905e4e4d1e5bfb059d8ee7c238f1983a2cdcc23376723e04dd93896f8b3446379dbc63161f106fa1062170
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(18660);
 script_version ("1.3");

 script_name(english:"Hydra: Postgres");
 script_summary(english:"Brute force Postgres authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Postgres passwords through brute
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Postgres accounts and passwords by
brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Database name (optional) : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/postgres", 5432);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "postgresql_unpassworded.nasl");
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

port = get_kb_item("Services/postgres");
if (! port) exit(0);	# port = 5432;
if (! get_port_state(port)) exit(0);

nopass = get_kb_item('postgresql/no_pass/'+port);
if (nopass) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);
db = script_get_preference("Database name (optional) : ");

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
argv[i++] = "postgres";
if (db) argv[i++] = db;

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
    set_kb_item(name: 'Hydra/postgres/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following accounts on the Postgres server :\n\n' + report);
