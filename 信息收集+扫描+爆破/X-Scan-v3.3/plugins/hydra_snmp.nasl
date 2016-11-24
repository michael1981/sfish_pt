#TRUSTED 2cf9dbf214eb023918cfe4eff8fca26599447da0296b094f310d8b7d20104f76222078c985d276d75c67a0c4cca9d62978bb32a420e568afdbc94d25b975fe50332f036239825ca31635d6f8d2fa91725eb8af5a9eca6e517b19807342962523a2dcf876c6850197cb11e09e09673523c90cd6dec18ba8bc61d0068fcb74a4e77e8d8ab965c8728502ec59d1bc98a5d79d9966c2a5e0fb4d2d83e06c6fa69dc947312c958dc03e253562c12275954767982d19cab53ddd5690b6b771e6639b172e47a1776a5ad63820fb73981dcb75c0d6fac164dc4794124a9772d24a7d337f05b27f3ca04e11840f23bc050ca8f18fdad8a789d49d9c207c50d46ddfc729f5423744666b4523fdafdb41986a4a1ade69130eafe0f2d1a93d288ab8a2d018185b2a365472b9be3f00b2a78ad84c827dda5bfc1b00ee5861ab951f32ab59b5df1fe6b82db5ff586ba73abf1990c9bf4d8b91e5d5d24717801a8c187cd92a38c2556d97109f3b7bafa10de66a592e06d822a5ff865bd661d42bdc7904c2bf76150f43e4f081033e639da51033236210a0870f1f2698455c368b9e5b62eb26d1bd4fc98193ac22274ee25a066ac1dc5409e275bd3814fd03245618005b502fd0637f1ac74545b94791459371b20c66500ae5f8768e4a22d62a52508266586c15a20c431515c3fb31ff9bb6ae1e8ede2f37f94c1b304bfaa187fe9633fa02c2d31f
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15886);
 script_version ("1.6");

 script_name(english:"Hydra: SNMP");
 script_summary(english:"Brute force SNMP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SNMP passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SNMP passwords by brute force. 

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
 script_require_keys("Secret/hydra/passwords_file");
 script_require_udp_ports(161, 32789);
 script_dependencies("hydra_options.nasl", "snmp_settings.nasl");
 exit(0);
}

#
force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
}

port = get_kb_item("SNMP/port");
if (port) exit(0);
# Yes! We exit if we know the port, and thus some common community name
port = 161;
if (! get_udp_port_state(port)) exit(0);	# Not very reliable, though...

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

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
} else if (! empty)
 exit(0);

if (exit_asap) argv[i++] = "-f";

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
argv[i++] = "snmp";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/snmp/'+port, value: p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following SNMP communities :\n\n' + report);
