#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40773);
 script_version ("$Revision: 1.4 $");

 script_name(english: "Web Application Potentially Sensitive CGI Parameter Detection");

 script_set_attribute(attribute:"synopsis", value:
"An application was found that may use CGI parameters to control
sensitive information." );

 script_set_attribute(attribute:"description", value:
"According to their names, some CGI parameters may control sensitive
data (e.g., ID, privileges, commands, prices, credit card data, etc.). 
In the course of using an application, these variables may disclose
sensitive data or be prone to tampering that could result in privilege
escalation.  These parameters should be examined to determine what
type of data is controlled and if it poses a security risk.");

 script_set_attribute(attribute:"solution", value: 
"Ensure sensitive data is not disclosed by CGI parameters.  In
addition, do not use CGI parameters to control access to resources or
privileges." );

 script_set_attribute(attribute:"risk_factor", value: "None" );

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/25");
 script_end_attributes();

 script_summary(english: "Common sensitive CGI paramaters names");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

names = make_array(
"cmd",		"Possibly a command - try 'edit', 'view', 'delete'...",
"command",	"Possibly a command - try 'edit', 'view', 'delete'...",
"id",		"Potential horizontal or vertical privilege escalation",
"price",	"Manipulating this could allow for prince modification",
"admin",	"Potential vertical privilege escalation - try '1', 'yes'...",
"role",		"Potential privilege escalation - try 'admin', 'super'...",
"pwd",		"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"pass",		"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"passwd",	"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"password",	"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"user",		"Potential horizontal privilege escalation - try another user ID",
"usr",		"Potential horizontal privilege escalation - try another user ID",
"cc",		"Possibly credit card data - please examine it",
"expd",		"Possibly credit card expiration date",
"cvv",		"Possibly a credit card cryptogram" );


port = get_http_port(default:80, embedded: 0);

cgis = get_kb_list(strcat("www/", port, "/cgis"));
if (isnull(cgis)) exit(0);
t = get_port_transport(port);
# As get_kb_list may return an array with duplicated keys, we call
# make_list() to clean it, just in case.
cgis = make_list(cgis);

rep = "";
foreach cgi (cgis)
{
  r = eregmatch(string: cgi, pattern: "^(.+) - (.*)$");
  if (isnull(r)) continue;
  cgi_name = r[1];
  cgi = r[2]; 

  repcgi = "";  
  while (strlen(cgi) > 0)
  {
    r = eregmatch(string: cgi, pattern: "^([^ ]*) \[([^]]*)\] (.*)$");
    if (isnull(r))
    {
      r = eregmatch(string: cgi, pattern: "^([^\[\]]*) \[([^]]*)\] (.*)$");
      if (isnull(r))
      {
        err_print("Cannot parse: ", cgi);
        break;
      }
    }
    name = tolower(r[1]);
    cgi = r[3];
    foreach k (keys(names))
      if (k == name)
      {
	a = names[k];
	if (t > ENCAPS_IP)
          a = str_replace( string: a,
	      		   find: "vulnerable to sniffing or ",
			   replace: "vulnerable to ");
        repcgi = strcat(repcgi, r[1], ' : ', a, '\n');
	break;
      }
  }
  if (strlen(repcgi) > 0)
  rep = strcat(rep, 'Suspicious parameters for for CGI ', cgi_name, ' :\n\n', repcgi, '\n');
}

if (strlen(rep) > 0)
{
  security_note(port: port, extra: '\n'+rep);
  if (COMMAND_LINE) display(rep);
}
