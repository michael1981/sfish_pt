#TRUSTED 5e853b4ea69fdcbfc660cd39ec4027167fbd055aa586740d15918f3251bbbf0554c0548947ebfae0cde1e5ee423cd7ce9816860889346c7cec9179c13aca98de80fff5e8c4afa2919b8c7695fb9de72a96ddcbda96d37add8cbf3e38f466740ed79d73867cdb71744a6e9694b8eadac9c2ab30641b84732a60871680193395cec360160c1d036963c201ccdf1defbf44ac459da89d9d5b07cbfc9f344ff81eea19d13d75d50171266fabc44bf49a9d3a3dfee74d0290977f8023b09a111bdadad006793cf84f7328af81954270770d38d79c1d6c31ff821c57eae969b1c78418e7350025f5cd8f5af5ed782259ba223f293583c53c253dec93c90d3a3d97873acc1888e4397970d42018050279cc0cfe6a23de9c65cd37b99ffc30843bef5fa3540c711c866c786b6137b07ffe67016aa135466e6704ac32c0fe4dbe30088768513776c6dae1b5dd52a3665d089e49103e31dd0db3d7c5652ea3517a6a91d3851d2a49806bca72a20fc035de09abbda5feec61bf8b786ab7219411c4a2fd38ed77c75fdd52b98fa746e192bc302857fa9631fa23b52c0abf79779d82be922c329359f76a1f63ca0e1412309887b49bfa2a72fb62253906063816cb10dbf77def2cd54edc6135461792eba8ebeb457ef3a68ecaaf12c9c07db56f077a20d0a0aedfc206b47fc3164ac7fc07b955987cda8fc68bc8117070eac36c32b60728bc8c
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15877);
 script_version ("1.7");

 script_name(english:"Hydra: LDAP");
 script_summary(english:"Brute force LDAP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine LDAP accounts through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find LDAP accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "DN : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/ldap", 389);
 # find_service does not detect LDAP yet, so we rely upon amap
 # However find_services will detect the SSL layer for LDAPS
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "external_svc_ident.nasl", "ldap_detect.nasl");
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

port = get_kb_item("Services/ldap");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

dn = script_get_preference("DN : ");
if (! dn) exit(0);

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
argv[i++] = "ldap";
argv[i++] = dn;

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
    set_kb_item(name: 'Hydra/ldap/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following accounts on the LDAP server :\n\n' + report);
