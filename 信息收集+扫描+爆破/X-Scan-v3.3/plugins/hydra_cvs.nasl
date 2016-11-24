#TRUSTED 084e96387ef96cc04414cdd560274af66b8bc2dcbcd477f22cc1e1d1b9325cdda5be89d8cbdaeb570b550b89d7e6fbd00ae2a5456a771b62a58aed53a5d216ca6ab442a9cd28e76f131d2b884d71132f6d4fa009ce97a58767ef21f9dfcb0d8eac266d26496eb4f4ad6b52dad070bfc3ffe10d5a9ed551eaa570e535a0d42d6fa82f80377181168e4d0208874610f27bdcf7fa7eb1e428df50888a7e6f03565a50efce03fac7a78246b9aaa1a61c61309356704f2dd7c005b459f3c7007a17bd94834515cbbb6cab3bbfa03fc3062594b99e873cad8bf6193b2adf45fa51a98f28e7dd465d1afac84f53537ebb8cc154b71061509479e1ae90b934e649ce63f7808cdf1bca3f8be261be9c13238f11011f0e755c5da5a5553c7a4bad933b278563e77652c69d0cf10f22b702da4d1ad679031286ee1d9042d90e8d526406f3be91d90f77bab695b0c97e0183f4fed24facc2e6a1bc591184911bb087d35da76eba5c5cc92c71d0e3f4dece9a04df3ba2d5acee085535b808ffd02cba36456fe842b619a2af4a0c6b6b5b1199a846e734d100c9bce9e67e74b6e1e39c79ea23a7452c7deccb63543adf965e25b866dc7f6c1714336bc08832dae37d53ec5a434f7ca403d82a7e4aa12ba8c8e3cbf67418db700f05fcd771a4deaf132d09e2d13897156b568a94e0ca6ba07d02789ee969449e883f9d0ce80c725835442e834ab7
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15871);
 script_version ("1.5");

 script_name(english:"Hydra: CVS");
 script_summary(english:"Brute force CVS authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine CVS passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find CVS accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_timeout(0);
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "cvs_detect.nasl");
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

port = get_kb_item("Services/cvspserver");
if (! port) exit(0);	# port = 2401;
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
argv[i++] = "cvs";

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
    set_kb_item(name: 'Hydra/cvs/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following CVS accounts :\n\n' + report);
