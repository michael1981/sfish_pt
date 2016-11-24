#TRUSTED 81989fbb06704a8a1681b8c90ad78b76a481337cd6ef0e838b09d3f3554ddbe89e819fe805fefec1b2e7bf772596743270ed53711d8a3c9c32fba6114ea5ea4b5a70c80fbd94aab68b6a6cda2afc50e8fd935309a3674b1e8e896332f43024855b5ebb4220d93fb25ebedd483eddfdccc8a87da4e64e8a0b9e9a4a00837c1ab9005795e78a75b23eda4233c22a3225056277b7703abb2ccf44a7ab7e82aa2025b1268df4b3136af789fcae77ff3af46bcb9230e2eb68113f1a6fe9194d78c782e90c1fe355490897ab62427de18af92528e34ba960406cbad951a0f3449a25ab296e2eee4d82ce468fb04788ad2a1cd90a03b46339fc0b91795a8ca5031a4a5a847c8a3f89e7e9d62f15265dabe7afcfce69dbdee727d82904eca6c39e845b7a2ac93a34ed543c004ed78a13b11a02c5f630c1436824e127aaf3ffb23b6efa6daa1e44f4ab0e99789707366771da2d4af617fd596e471c0d2c91235616b2377d51b092e4aedb87cd4f4d50cb76eed104328b4ba1009c931e6a36c860dde97b25469def1f1a7e78336696f16960d44fc44d491686d4218d620c56825fbabbcfbf37b64f2c0b3c380ce52877cf80254e61500438de150702c175ba1e821ea5bb03ad7a0265480afcff89aece138ac9fc0d22835f4e1cb5a7aaaeae069647d469490b56040725854d9a43a30337a09fce5f815d8b22d8924c5c8899fe81bfb7e9b8
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15869);
 script_version ("1.3");

 script_name(english:"Hydra: Cisco");
 script_summary(english:"Brute force Cisco authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Cisco passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Cisco passwords by brute force. 

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
 script_require_keys("Secret/hydra/passwords_file");
 script_require_ports("Services/telnet", 23);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
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

# Check that this is a router
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0);

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
} else if (! empty)
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
argv[i++] = "cisco";

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
    set_kb_item(name: 'Hydra/cisco/'+port, value: p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to find the following CISCO passwords :\n\n' + report);
