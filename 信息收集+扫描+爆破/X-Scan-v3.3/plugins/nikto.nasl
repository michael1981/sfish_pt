#TRUSTED 19ef1a4d6d5975f17ee3aa5929e773bf589cbb2d6c3a968b21b12da45c60ba3f797279dd52c7c0c410bed31f65e3ee6be32cd5963b9e891dcc2d30348d549409494c258acde0cabf1e6ab585b94db74d737aa99a3d9db5f6d8841d62c1fa22530af8663cbff613bf11cd3713a29003bf3371fa561df0af59c74fcef52dc156d4e323d11e03b1a45b4674f4ec9d0129ea37c835c823ede4fe130719d00375b71ebb7e06a5d1d94c6a529cd90401939eb3a3ec6144f33796f36fa92079dc956a3480a3c2456e4d0bb600c4ddfdf995fa493715417626b6aff450a15106b735a0573fa8bf6d8e02b8571de1a1165a1ecd3e58207469766c105bee9c3fccc6e0f9a9818a8373ef1a30a3a6ce0b0de7a0c16523ca219ee5c2fec3b6cda1986b69bd4e894e61b667469de9fd1a287a3e303ec53c40163d117c6d2e6196bb16cd8b4a6f7bf570b399cc0d483c5fe7bc6406c2b4ad07ab0197e6783818516de7a1178e2c52c829fbb6ab2616a6f3b1529a4ea74769a3d284540c99230e9c4bd24c668ef0787e49047212c55b1acaa8d9ecc60f91a7971573ad460a47279e118c2d35c09b3025534563ade2d492d44b1f2a3e711ae05f69f09403a485654f4871330507f2372c806bb7f9858105de1abafe2b299972231184eafc3c262a2986e5b6ec2a5993f0900f6c0053d2528c3a2ce4ba75ec51004d343d78a35e0b0526e5e6bc5029
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("pread")) exit(0, "nikto.nasl cannot run: pread() is not defined");
cmd = NULL;

if ( find_in_path("nikto.pl") ) cmd = "nikto.pl";
else if ( find_in_path("nikto") ) cmd = "nikto";

if ( ! cmd && description) {
	if ( NASL_LEVEL < 3000 ) exit(0);
	exit(0, "Nikto was not found in $PATH");
}

include("compat.inc");

if(description)
{
 script_id(14260);
 script_version ("1.25");
 script_name(english: "Nikto (NASL wrapper)");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin runs Nikto2." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Nikto2 to find CGI scripts, identify potential flaws,
etc. 

See the section 'plugins options' to configure it."
);
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.net/nikto2" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_end_attributes();

 
 script_summary(english: "Run Nikto2");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencies("http_version.nasl", "find_service1.nasl", "httpver.nasl", "logins.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(0);
 script_add_preference(name:"Enable Nikto", type:"checkbox", value:"no");
 script_add_preference(name:"Disable if server never replies 404", type:"checkbox", value:"yes");

 script_add_preference(name:"Root directory", type:"entry", value:"");
 script_add_preference(name:"Pause between tests (s)", type:"entry", value:"");
 script_add_preference(name:"Scan CGI directories",
                       type:"radio", value:"User supplied;All;None");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 1 Show redirects");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 2 Show cookies received");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 3 Show all 200/OK responses");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 4 Show URLs which require authentication");
 script_add_preference(type: "checkbox", value: "no", name: "Display: D Debug Output");
 script_add_preference(type: "checkbox", value: "no", name: "Display: V Verbose Output");

 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 1 Interesting File / Seen in logs");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 2 Misconfiguration / Default File");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 3 Information Disclosure");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 4 Injection (XSS/Script/HTML)");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 5 Remote File Retrieval - Inside Web Root");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 6 Denial of Service");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 7 Remote File Retrieval - Server Wide");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 8 Command Execution / Remote Shell");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 9 SQL Injection");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 0 File Upload");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: a Authentication Bypass");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: b Software Identification");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: c Remote Source Inclusion");
 if ( NASL_LEVEL >= 3000 )
  script_add_preference(type: "checkbox", value: "no", name: "Tuning: x Reverse Tuning Options (i.e., include all except specified)");

 script_add_preference(type: "checkbox", value: "no", name: "Mutate: 1 Test all files with all root directories");
 script_add_preference(type: "checkbox", value: "no", name: "Mutate: 2 Guess for password file names");
 if ( NASL_LEVEL >= 3000 )
 {
  script_add_preference(type: "checkbox", value: "no", name: "Mutate: 3 Enumerate user names via Apache (/~user type requests)");
  script_add_preference(type: "checkbox", value: "no", name: "Mutate: 4 Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)");
 }

 exit(0);
}

#

function my_cgi_dirs()	# Copied from http_func.inc
{
 local_var	kb;
 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb)) kb = make_list("/cgi-bin", "/scripts", "");
 else kb = make_list(kb, "");
}

if (! COMMAND_LINE)
{
 p = script_get_preference("Enable Nikto");
 if ( "yes" >!< p ) exit(0, "Nikto is not enabled (per policy)");
}

if (! defined_func("pread"))
{
  set_kb_item(name: "/tmp/UnableToRun/14254", value: TRUE);
  display("Script #14254 (nikto_wrapper) cannot run\n");
  exit(0, "nikto.nasl cannot run: pread() is not defined");
}

if (! cmd)
{
  display("Nikto was not found in $PATH\n");
  exit(0, "Nikto was not found in $PATH");
}

user = get_kb_item("http/login");
pass = get_kb_item("http/password");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0, "No open HTTP port");

# Nikto may generate many false positives if the web server is broken
p = script_get_preference("Disable if server never replies 404");
if ("yes" >< p || "no" >!< p)
{
no404 = get_kb_item("www/no404/" + port);
if ( no404 ) exit(0, "Web server does not return 404 codes");
}

i = 0;
argv[i++] = cmd;

p = script_get_preference("Scan CGI directories");
if (p)
if ("User supplied" >!< p)
{
 argv[i++] = "-Cgidirs";
 argv[i++] = tolower(p);
}
else
{
 v = my_cgi_dirs();
 n = 0;
 if (! isnull(v))   n = max_index(v);
 if (n > 0)
 {
  l = "";
  for (j = 0; j < n; j ++)
  {
   l = strcat(l, v[j]);
   if (! match(string: v[j], pattern: "*/")) l = strcat(l, "/");
   l = strcat(l, " ");
  }
  argv[i++] = "-Cgidirs";
  argv[i++] = l;
 }
}

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

display='';
l = make_list("Display: 1 Show redirects", 
	"Display: 2 Show cookies received",
	"Display: 3 Show all 200/OK responses", 
	"Display: 4 Show URLs which require authentication",
	"Display: D Debug Output",
	"Display: V Verbose Output");

foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) display = strcat(display, substr(opt, 9, 9));
}

if (display)
{
 argv[i++] = "-Display";
 argv[i++] = display;
}

mutate = '';
l = make_list("Mutate: 1 Test all files with all root directories",
	"Mutate: 2 Guess for password file names",
	"Mutate: 3 Enumerate user names via Apache (/~user type requests)",
	"Mutate: 4 Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)");
foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) mutate = strcat(mutate, substr(opt, 8, 8));
}
if (strlen(mutate) > 0)
{
 argv[i++] = "-mutate";
 argv[i++] = mutate;
}

p = script_get_preference("Pause between tests (s)");
p = int(p);
if (p > 0)
{
 argv[i++] = "-Pause";
 argv[i++] = p;
}

p = script_get_preference("Root directory");
if (strlen(p) > 0)
{
 argv[i++] = "-root";
 argv[i++] = p;
}


l = make_list("Tuning: 1 Interesting File / Seen in logs",
	"Tuning: 2 Misconfiguration / Default File",
	"Tuning: 3 Information Disclosure",
	"Tuning: 4 Injection (XSS/Script/HTML)",
	"Tuning: 5 Remote File Retrieval - Inside Web Root",
	"Tuning: 6 Denial of Service",
	"Tuning: 7 Remote File Retrieval - Server Wide",
	"Tuning: 8 Command Execution / Remote Shell",
	"Tuning: 9 SQL Injection",
	"Tuning: 0 File Upload",
	"Tuning: a Authentication Bypass",
	"Tuning: b Software Identification",
	"Tuning: c Remote Source Inclusion",
	"Tuning: x Reverse Tuning Options (i.e., include all except specified)");
tuning= '';
foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) tuning = strcat(tuning, substr(opt, 8, 8));
}
if (strlen(tuning) > 0)
{
 argv[i++] = "-Tuning";
 argv[i++] = tuning;
}


p = int(get_preference("checks_read_timeout"));
if (p > 0)
{
 argv[i++] = "-timeout";
 argv[i++] = p;
}

argv[i++] = "-host"; argv[i++] = get_host_ip();
argv[i++] = "-port"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

#p = script_get_preference("Force scan all possible CGI directories");
#if ("yes" >< p) argv[i++] = "-allcgi";
p = script_get_preference("Force full (generic) scan");
if ("yes" >< p) argv[i++] = "-generic";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: cmd, argv: argv, cd: 1);
if (! r)
{
 s = '';
 for (i = 0; ! isnull(argv[i]); i ++) s = strcat(s, argv[i], ' ');
 display('Command exited in error: ', s, '\n');
 exit(0, "Command exited with an error");	# error
}
if ("No HTTP(s) ports found" >< r) exit(0, "Nikto did not find any HTTP ports");

report = '\nHere is the Nikto report :\n\n';
foreach l (split(r))
{
  #display(j ++, "\n");
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, extra: report);
if (COMMAND_LINE) display(report, '\n');
