#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26196);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5255");
  script_bugtraq_id(25894);
  script_xref(name:"OSVDB", value:"37420");

  script_name(english:"Google Mini Search Appliance search Script ie Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in Google Search Appliance");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Google Search Appliance / Mini Search Appliance fails to
sanitize user-supplied input to the 'ie' parameter used in the search
interface.  An unauthenticated remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site." );
 script_set_attribute(attribute:"see_also", value:"http://blogs.zdnet.com/security/?p=539" );
 script_set_attribute(attribute:"see_also", value:"http://www.xssed.com/news/40/Google_Search_Appliance_is_vulnerable_to_XSS/" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4567b94 (requires credentials)" );
 script_set_attribute(attribute:"solution", value:
"Apply the fix as discussed in the vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("google_search_appliance_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_kb_item("www/"+port+"/google_search_appliance")) exit(0);


# Send a request to determine how the appliance is configured.
w = http_send_recv3(method:"GET", item:"/", port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

# If it looks like we're redirected to the search form...
if ("Location: /search?" >< res && "site=" >< res)
{
  # Extract the parameters.
  param_str = strstr(res, "Location: /search?") - "Location: /search?";
  param_str = param_str - strstr(param_str, '\r\n');

  params = make_array();
  while (strlen(param_str) > 0)
  {
    i = stridx(param_str, "&");
    if (i == -1)
    {
      p = param_str;
      param_str = "";
    }
    else if (i == 0) break;
    else 
    {
      p = substr(param_str, 0, i-1);
      param_str = substr(param_str, i+1);
    }

    i = stridx(p, "=");
    if (i > 0 && i < strlen(p)-1)
    {
      key = substr(p, 0, i-1);
      val = substr(p, i+1);
      params[key] = val;
    }
  }

  if (params["site"] && params["client"])
  {
    # Send a request to exploit the flaw.
    xss = string("<script>alert('", SCRIPT_NAME, "')</script>");

    w = http_send_recv3(method:"GET",
      item:string(
        "/search?",
        'ie=">', urlencode(str:xss), "&",
        "site=", params["site"], "&",
        "output=xml_no_dtd'&",
        "client=", params["client"], "&",
        "proxystylesheet=", params["proxystylesheet"], "'"
      ), 
      port:port  
    );
    if (isnull(w)) exit(1, "the web did not answer");
    res = w[2];

    # There's a problem if our exploit appears along with the time in a form.
    if (
      string('">', xss, '><INPUT TYPE=hidden name=client') >< res ||
      string('input type="hidden" name="ie" value=">', xss, '>') >< res
    ){
     security_warning(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
  }
}
