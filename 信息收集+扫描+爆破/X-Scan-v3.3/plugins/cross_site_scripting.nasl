#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10815);
  script_version("$Revision: 1.60 $");

  script_cve_id("CVE-2002-1060", "CVE-2003-1543", "CVE-2005-2453", "CVE-2006-1681");
  script_bugtraq_id(5305, 7344, 7353, 8037, 14473, 17408);
  script_xref(name:"OSVDB", value:"18525");
  script_xref(name:"OSVDB", value:"24469");
  script_xref(name:"OSVDB", value:"42314");
  script_xref(name:"OSVDB", value:"4989");
  script_xref(name:"OSVDB", value:"58976");

  script_name(english:"Web Server Generic XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a web server that fails to adequately
sanitize request strings of malicious JavaScript.  By leveraging this
issue, an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Cross-site_scripting" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_end_attributes();
 
  summary["english"] = "Checks for generic cross-site scripting vulnerability in a web server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default: 80, embedded: 1);

file = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789");
exts = make_list(
  "asp",
  "aspx",
  "pl",
  "cgi",
  "exe",
  "cfm",
  "html",
  "jsp",
  "php",
  "php3",
#  "phtml",
#  "shtml",
   "cfc", 
   "nsf",
   "dll",
   "fts",
   "jspa",
   "kspx",
   "mscgi",
   "do",
   "htm",
   "x",
   ""
);
exploits = make_list(
  # nb: while this isn't valid Javascript, it will tell us
  #     if malicious script tags are output unfiltered.
  string("<script>", SCRIPT_NAME, "</script>"),
  string('<IMG SRC="javascript:alert(', SCRIPT_NAME, ');">')
);


failures = 0;

dirs_l = NULL;
# If we are in paranoid mode, we want to reduce the FPs anyway.
if (thorough_tests || report_paranoia > 1) dirs_l = cgi_dirs();

if (isnull(dirs_l)) dirs_l = make_list("/"); 

foreach dir (dirs_l)
{
  len = strlen(dir);
  if (len > 1 && dir[len-1] != "/") dir = strcat(dir, "/");

foreach ext (exts)
{
  foreach exploit (exploits)
  {
    if (" " >< exploit) enc_exploit = str_replace(find:" ", replace:"%20", string:exploit);
    else enc_exploit = exploit;

    if (ext) urls = make_list(string(dir, file, ".", ext, "?", enc_exploit));
    else
      urls = make_list(
        # nb: does server check "filenames" for Javascript?
        string(dir, enc_exploit),
        enc_exploit,
        # nb: how about just the request string?
        string(dir, "?", enc_exploit)
      );

    foreach url (urls)
    {
      # Try to exploit the flaw.
      r = http_send_recv3(method: 'GET', item:url, port:port, fetch404: TRUE);
      if (isnull(r))
      {
        failures ++;
        if (failures > 3)
 	  exit(0);
	continue;
      }

      if (exploit >< r[2])
      {
        set_kb_item(name:string("www/", port, "/generic_xss"), value:TRUE);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

        if (report_verbosity)
        {
          report = strcat('\nThe request string used to detect this flaw was :\n\n', url, '\n\nThe output was :\n\n', r[0], r[1], '\n');

	  idx = 0;
	  lines = split(r[2], keep: 1);
	  foreach l (lines)
	    if (exploit >< l) break;
	    else idx ++;
	  i1 = idx - 3;
	  if (i1 < 0) i1 = 0; else report = strcat(report, '[...]\n');
	  for (i = i1; i < idx + 3 && i < max_index(lines); i ++)
	    report = strcat(report, lines[i]);	  
	  if (i < max_index(lines)) report = strcat(report, '[...]\n');

          security_warning(port:port, extra:report);
	  if (COMMAND_LINE) display(report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
}
