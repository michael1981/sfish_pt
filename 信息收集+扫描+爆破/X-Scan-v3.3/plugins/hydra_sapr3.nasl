#TRUSTED 7e2116814a16801bcbb2dba556e257c2b8e756dddd8abd34a32967daaf936f12de17b1bb2f7bf72c67277e19eba81cec4006795cfa772b7e3f3a46d2ab0b1275f787cfb59eeca9109bb56c38a6e06601d01813ce80df3aa9fdec46745c39a341aa785a2d0be1c76eadb4971eb5241ccfd5b28705e12af68abbd77de525202a9e76a0c5256655d172c68800335efb0ee9a88c99d45c14cae5cf7ae34fcd602d64e3aeb2fd2d5d21a7e23d5b2cd3475f37ab76b9f26fa7441abba50552567116d0c8cd1f396a5c9981d625e2110ef7c3e9e4a2619f1fab8a4bb657b2fb831a75ab85bb245f6d1bf0434b3d12b84331bf2be97751392cdd874e65513c52f48151841a5884b6615c859d2fbe8a735c1224d67356939bdfede2631dff0a0d937a90b4debcc3ca010573b82af7083ade270db131be64e251d662e3e20ca024500a28af1a1c88149f7864ee695f609d5ff3b0ccb9316c7cfb14f1ae7d696bf0f01d9bb1bf7c23aae17fb3af6f44ac10563d5835548764fe942e7b4317b487e3b7af254021d9e89e263ab916094e03f44f4b10c7b919a64a2efcaf8c94a42bf313798bacd2efd346fd94312cd5a84245c5ccf3f3bbd8898bb7ddced1609a2b8eb332506d22c09a37f806ad2c655efa32c681dbbb64ae8fb8cc9d7000b54c957865969e3283c7da5a87cb6741336b4947af811ecbbbbb12a9899d01208687a62b942fb445
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15883);
 script_version ("1.6");

 script_name(english:"Hydra: SAP R3");
 script_summary(english:"Brute force SAP R3 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SAP R3 passwords through brute force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SAP R3 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Client ID (between 0 and 99) : ", type: "entry", value: "");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/sap-r3", 3299);
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "external_svc_ident.nasl");
 exit(0);
}

#
force = get_kb_item("/tmp/hydra/force_run");
if (! force)
{
 thorough = get_kb_item("global_settings/thorough_tests");
 if ("yes" >!< thorough) exit(0);
}

logins = get_kb_item("Secret/hydra/logins_file");
if (logins == NULL) exit(0);

port = get_kb_item("Services/sap-r3");
if (! port) exit(0);	# port = 3299;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

id = script_get_preference("Client ID (between 0 and 99) : ");
if (! id) exit(0);
id = int(id);
if (id < 0 || id > 99) exit(0);

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
argv[i++] = "sapr3";
argv[i++] = id;

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
    set_kb_item(name: 'Hydra/sapr3/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    extra: '\nHydra was able to break the following SAP R3 accounts :\n\n' + report);
