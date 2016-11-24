#TRUSTED 5b02d715ea8bb530c06adebb3791e50dba17ff05e1b21a6c55f265a612f65efadbb529821d4d053cd9346daa9440f502f6004798afd822a8f3c113c74759c4a63257608185d98a17e84c64ff8f1420343ca4761fbe832a97dd5f0bcddd012f8820ae0e560ec214a4a95a23a0789dcc7b1dae37468d1ebf06fb268e4a45fda2f0f86ecf824fbbf479c7e70196fc42fa0b11a76a8ab22e36b4adb6090b853a41848c3a121ad2224a338fff976846ea947364c343ca3d3b1515c7fa4f1dfc167e26f3884876ff94d84d067e3cc193ab2ae8dd53f15e23a2d4cce7617dbb00bac0f014f7f37d20b69d4f4d0cbe3a739119e27476acfee90c448699b61f80419329bd25742dbf1fd72283fb019b90f3a27aec52a4688b2ea6607176186e210e29f1cb8ff5d58b20e20b6f77482920dcc5946ff560897101885a55f90b6e907d6f8d455a2299421e8f308776d20c690b1e0fa733000d13a838cd889d3154ce29d17a86cf8e51613c2fc9e0e761aa035e6c877efb513898d3488036f5f391d5a9360c07cca8c074d84bddb59d5bff86ba44e4b64811dd478ed91057e621aba1b27a59a7931ed97ee0e775162ccab61c00c5d578d759e65bebb924fe93e534413155f6c58a4bc9b8a59ca764e35ecc4c23aa97f2284c6d5f332de9bee14772867d59ae7d374c84bd0b67ee1448010f491a8734cce3050fa9e800c8230d0234786678a04a
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15873);
 script_version ("1.11");

 script_xref(name: "OWASP", value: "OWASP-AUTHN-004");
 script_xref(name: "OWASP", value: "OWASP-AUTHN-006");
 script_xref(name: "OWASP", value: "OWASP-AUTHN-010");

 script_name(english:"Hydra: HTTP");
 script_summary(english:"Brute force HTTP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine HTTP passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find HTTP passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 
 script_add_preference(name: "Web page :", value: "", type: "entry");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/www", 80);
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

port = get_kb_item("Services/www");
if (! port) exit(0);	# port = 80;
if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/broken") ) exit(0);

# Check that the server is up & running
soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
r = recv_line(socket: soc, length: 4096);
close(soc);
if (r !~ '^HTTP/1\\.[01] +[0-9][0-9][0-9] ') exit(0);

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
#if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

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
if ( tr >= ENCAPS_SSLv2 )
 argv[i++] = "https-get";
else
 argv[i++] = "http-get";

opt = script_get_preference("Web page :");
if (! opt)
{
  v = get_kb_list('www/'+port+'/content/auth_required');
  if (!isnull(v)) opt = v[0];
}
if (! opt) exit(0);
# Check that web page is forbidden
soc = http_open_socket(port);
if (! soc) exit(0);
send(socket: soc, data: 
 strcat('GET ', opt, ' HTTP/1.1\r\nHost: ', get_host_name(), '\r\n\r\n'));
r = recv_line(socket: soc, length: 512);
http_close_socket(soc);
if (r =~ '^HTTP/1\\.[01] +40[13] ') exit(0);
#
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
    set_kb_item(name: 'Hydra/http/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following HTTP accounts :\n\n' + report);
