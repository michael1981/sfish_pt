#TRUSTED 72d38fe3b35b111a483bf64f53c6ec1bfecea8533b18ffb51b048c47fefb93074477d8326d427d0769f7fde1f98e044a93b79378e072d77fc5dfe2526297f4094fdf0b7dd3530f97cf6783d8693980970e4eb6ceaef0af806e121ee1da554348baf3bfa7b4877db2cb6ce4d9fa2e7a2225fe9d6fb3c42b8f129abdce4a358e8c00b9d0a6b00a8337bf5a1ef8bcea312dfa7516f88c67975354a90c2290f8a692e69eaf044f76e33d9dac4471aa76fdebb9e570632079347b4e712db2b1e82f855df963198de75160a2118a6899ef9a7e4106d88d092e0402b075154e372e65a804031c0d2044bd4654b8253527970348d72ea94c0d2aafbf5a560a1a940438a9a48c36f1b2484be5c20933efebe7bb8d83cace7faa1094589f4fd9b2484a1bf23cb29d35dbc3d3ed1bf53a99c960cdf2ee549c484d124aed30472e73a977f52d51fe9dd2b12283828679b744e6a866a0964c44b0f8c44bb92d72a74fe2eabf9faa5b19a2ab0aa449de69d306f24d42b7925d52f54092e57a18b91efe52b1c08a99c9e5079166675260ab6659f49ce1c2455175349fabc76d9f9d6f6abaa9eecfc7eee08495141ea42e45604620b17d29c8abdb02987565ac3dbba7d2963519d0538e1b35a933a42951910401101d63d55d205e86614a4ff708a8b3fb33d4791b3d8be2159984beb47a75242f03431874b839fdb059d58036e947f0b9da636b59
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15880);
 script_version ("1.5");

 script_name(english:"Hydra: PCNFS");
 script_summary(english:"Brute force PCNFS authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine PCNFS passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find PCNFS accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_udp_ports(640);
 script_dependencies("hydra_options.nasl", "external_svc_ident.nasl");
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

port = get_kb_item("Services/udp/pcnfs");
if (! port) exit(0);	# port = 640;
if (! get_udp_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

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
argv[i++] = "pcnfs";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*)? password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/pcnfs/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following PC-NFS accounts :\n\n' + report);
