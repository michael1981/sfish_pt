#TRUSTED 5de1d188bf0c8359c206f7e8ae66ce22e96eb6238b33d8a94371d5f508ce11fb8f575bde907e80ac81c32dc3c59f069480a565b1dfc33024d07604fadac801cf94ee974064d93d9e8de1b8c7bd0db103812c5243723f6f19529449123f5f29f98e98220346325dda98c8517cbee3d880a11e635ac7eb1cbbdd055dbe9f67234ac1c978ee95da2ae1c90d69fc87083b374fcb315453d06439ca6ca6260e77a0d6495f0738439989d14bf5afa6ac441f2a91a55640c096e8618c9eb8adafd7d725d38ec06e9fd0ac05194098d20ff5a24cca848032a34a78ff06b8222dcef5750b9b038d3bfc14dd62114b3121aa8851c729176d4458afccaa74ca721cddfe3bea9c92cb374a37a03658f3ab7c871b22404d5146e769293f9e46d703439a3679344b4c63884d0e83c025e8b4c6a2be1616769fe5b35b863d46e98b6bbd05b25bf967cfc9fcff93a6532d6f8401ca72520fcd0644d42992a06f0cdcb777db6e565d5eeadf3bef741cb78e3a2da415d3d5e46ff7509cb1770645077f03f7c94e995fd2d76d1740518c93090e785b45384408640131caccf34bad336ffe78c033b2b41b2cd2256f9cf1e8ab2bdc2854b793800f06ea0e80c8932e7821d4d5dd0915a8965a1dc2ddfc8094ae310edab9f4dcfdcb5beb5adbaac797f2b37656b0c9345e8a772a2360a4bd09be87356e3e0b8ee1064ddf2c9423d4edb65a618670602b19
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15874);
 script_version("1.5");

 script_name(english:"Hydra: HTTP proxy");
 script_summary(english:"Brute force HTTP proxy authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine HTTP proxy passwords through brute
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find HTTP proxy accounts and passwords by
brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Web site (optional) :", value: "", type: "entry");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/http_proxy", 3128);
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

logins = get_kb_item("Secret/hydra/logins_file");
if (logins == NULL) exit(0);

port = get_kb_item("Services/http_proxy");
if (! port) exit(0); # port = 3128;
if (! get_port_state(port)) exit(0);

# www.suse.com by default
opt = script_get_preference("Site (optional) :");
if (!opt) site = 'http://www.suse.com/';
else if (opt !~ '^(http|ftp)://') site = strcat('http://', opt);
else site = opt;
host = ereg_replace(string: site, pattern: '^(ftp|http://)([^/]+@)?([^/]+)/.*',
	replace: "\3");
if (host == site)
 req = 'GET '+site+' HTTP/1.0\r\n\r\n';
else
 req = 'GET '+site+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n';
s = open_sock_tcp(port);
if (!s) exit(0);
send(socket: s, data: req);
r = recv_line(socket: s, length: 1024);
close(s);
if (r =~ "^HTTP/1\.[01] +[234]0[0-9] ") exit(0);	# Proxy is not protected

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
argv[i++] = "http-proxy";

if (opt) argv[i++] = opt;

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
    set_kb_item(name: 'Hydra/http-proxy/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following accounts on the HTTP proxy :\n\n' + report);
