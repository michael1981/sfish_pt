#TRUSTED 27755c6f6529f4fce8ba5305f8a5f855c8e07979e7ce52793a3877c93ca67ef0eedbabafb99316021d5b8f18fd1486f9f65dd5af088674b1f18f86e45a606d7e17a59bffe4ae26d60fd83ee83a49574bc618ba132382c35f10ba6cb680ba9a28f97be9db56df01b2493f5ea04dfdbe9179b46b057a1c1cc232ea9a1643dffaee73d7ebb2d6ea9febf2dac48958172b89642d4d8c5ef0aa535476c5632632b381c438b410e15bc69ca2c7eaf95a7204838c6f3e86ce7725cd6d0d51dfd45d3b702d53c18035f551464e80607205604c2992b087c4a5bcb1851f4e2e39a47dd6ca6468a866821cd63a0be96ba6005d6586c59b757b8ee8c4163ac858bb822a88b7026d47fd2c52ad5c91482eb914e1339ac1f3ab4d2e0579a1bd48891f3e22a863a0d140df8ef9a27b28f925a3a20c2aa3972b35533a04b40ad5a8b32e5f7ea7b5daee3ef851976e3ec89ae0b6ca44fbdc6a1178895ba7552021b819c4ae4ebc1e8dd8588624d26d0215f028f529c0342a50878833f4233e4ff028811cd6dc56cdf72225771ed544e8dd4934fc571e799cdf3aacbccd3442de9cfef5ec9aecf9726714b8cef85c67e10a195c5338829fdd2a4fa2ee15ba4eb0ac83388dedd471b6543c023a0cf5e3d934e8dd5cdedc88dd2a506225fe1ae42afdc5fcd5cc3b74916eb7cc03419c7a7a4459bfc63c699011a12e2132a2a68c190cc65936ed6a98eb
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("script_get_preference_file_location")) exit(0);
if ( ! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15884);
 script_version ("1.5");

 script_name(english:"Hydra: SMB");
 script_summary(english:"Brute force SMB authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SMB passwords by brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SMB accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Check local / domain accounts", 
	value: "Local accounts; Domain Accounts; Either", type: "radio");
 script_add_preference(name: "Interpret passwords as NTLM hashes", 
	value: "no", type: "checkbox");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports(139, 445, "SMB/transport");
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 exit(0);
}

#
force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
 if (! safe_checks()) exit(0); # Because of accounts lock out
}

logins = get_kb_item("Secret/hydra/logins_file");
if (logins == NULL) exit(0);

port = get_kb_item("SMB/transport"); port = int(port);
if (! port) exit(0);	# port = 445;
if (! get_port_state(port)) exit(0);

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
argv[i++] = "smbnt";	# what's "smb"?

opt = "";
p = script_get_preference("Check local / domain accounts");
if ("Local" >< p) opt = "L";
else if ("Domain" >< p) opt = "D";
else opt = "B";

p = script_get_preference("Interpret passwords as NTLM hashes");
if ("yes" >< p) opt += "H";
argv[i++] = opt;

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
    extra: '\nHydra was able to break the following SMB accounts :\n\n' + report);
