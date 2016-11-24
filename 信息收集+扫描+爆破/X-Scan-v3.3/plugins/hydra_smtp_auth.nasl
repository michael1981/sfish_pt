#TRUSTED 4db7af5c1d893e4b0b46ed17cc6bea3d155f9d4c1f6a7a17a1c2cd103b348ea1214a99a02fa554ba3d547e5e28ffa685901fe0cb762fd3d3d1f7d3bd301f15c0b53fc8522c78e8893340c3da5c4851651bf6dbd930cfcefcb9d827016844fc6b6166000ac78757cec494de60c42f23cdcba8c8f635f81066251fbfce106f4bba64b53eaccce8ae98782e2469e4a60a1d443abb25deb065a4aecfc77092a3a98dfc06be319ca70c68e5ad5ee8e25141d25e7c824df7fef620167d931f292bdad9ff989f0c3ba9a905e9f7763b598216e4b0c47a4287e16e63b8039e01d5a4edf990bdbde6ac8910f28f3900928e462989ca25ecaf8195cf69b54df077bd381c6c50d2971fd3959c676171e814a3f0ce8f24a3b87f1b91ca150b16c43d319f4f9434bb2578d33aa1677664f16a9e4ca0057102d9e63fa0b06ef23d74dbf052bdb5c055e525bb67222e772446f4b5cd41a3753adcd4628b5cf78db119e17dc6df9bfc15ce56136262c94452a90b0d0b7868b0fae3d2e753a21ad0e796d992814852f4d228fc0487fdc1aea5ef0589e0aa0acc72c315ee30651b076d2c7c57e50b416fb5b809248dbb5af4622c3c2eccb734de018eaa36399bde604f240b9df2dbbf1181398af91b2f9d0b6ed251f040577c8750306d14ffb9867ae99d5b53f7002a54896b9350febac48610aea50452c587f213371f6c7e4c9b6fab634d1a304bad
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15885);
 script_version ("1.5");

 script_name(english:"Hydra: SMTP AUTH");
 script_summary(english:"Brute force SMTP AUTH authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SMTP AUTH passwords through brute 
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SMTP AUTH accounts and passwords by
brute force. 

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
 script_require_ports("Services/smtp", 25);
 script_dependencies("hydra_options.nasl", "smtpserver_detect.nasl");
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

port = get_kb_item("Services/smtp");
if (! port) exit(0); # port = 25;
if (! get_port_state(port)) exit(0);
# NB: Hydra will exit if SMTP AUTH is not enabled

# Check that the MTA is up & running
soc = open_sock_tcp(port);
if (!soc) exit(0);
r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9] ') exit(0);
# Here we could send a EHLO & check that AUTH is supported...

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
argv[i++] = "smtp-auth";

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
    set_kb_item(name: 'Hydra/smtp-auth/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following SMTP accounts :\n\n' + report);
