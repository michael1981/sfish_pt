#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35779);
  script_version("$Revision: 1.10 $");

  script_name(english:"OS Identification : HTML");
  script_summary(english:"Identifies devices based on HTML output");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server can be used to identify the host's operating\n",
      "system."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote operating system can be identified by looking at the HTML\n",
      "returned from certain HTTP requests."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


ports = get_kb_list("Services/www");
if (isnull(ports)) exit(0);
ports = make_list(ports);


# Variables for each device:
#
# nb: for the arrays, *all* elements must be found for a match to occur.
# name		description of the device
# port_re       regex for port at which to look
# url		page to examine
# server	string found in Server response header (may be "" if there is *no* such header)
# server_re	idem, regex
# title		array of strings found in title
# title_re      array of regexes to match against the title
# body          array of strings found in body
# body_re	array of regexes to match against the body.

i = 0;
name      = make_array();
port_re   = make_array();
url       = make_array();
server    = make_array();
server_re = make_array();
title     = make_array();
title_re  = make_array();
body      = make_array();
body_re   = make_array();

name[i]      = "CISCO IP Telephone 7960";
port_re[i]   = "^80$";
url[i]       = "/";
server[i]    = "Allegro-Software-RomPager";
title[i]     = make_list(
                 "Cisco Systems, Inc."
               );
body_re[i]   = make_list(
                 '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) IP Phone 7960G? \\( SEP'
               );
i++;

name[i]      = "Dell Laser Printer";
port_re[i]   = "^80$";
url[i]       = "/";
server[i]    = "EWS-NIC4/";
title[i]     = make_list(
                 "Dell MFP Laser"
               );
i++;

name[i]      = "HP LaserJet";
url[i]       = "/";
server_re[i] = "(HP-ChaiSOE|Virata-EmWeb)/";
body_re[i]   = make_list(
                 "(/hp/device/this.LCDispatcher|<title> HP Color LaserJet)"
               );
i++;

name[i]      = "HDHomeRun Networked Digital TV Tuner";
port_re[i]   = "^80$";
url[i]       = "/";
server[i]    = "UPnP/";
title[i]     = make_list(
                 "HDHomeRun"
               );
body[i]      = make_list(
                 "Silicondust HDHomeRun&#8482;"
               );
body_re[i]   = make_list(
                 '<div class="S">Device ID: [0-9A-Fa-f]+<br',
                 'Firmware: [0-9]+'
               );

i++;
name[i]      = "SCO OpenServer";
url[i]       = "/dochome.html";
server[i]    = "NCSA/";
title[i]     = make_list(
                 "SCO Documentation Library"
               );
body[i]      = make_list(
                 "/FEATS/CONTENTS.html>SCO OpenServer"
               );

i++;
name[i]      = "Sipura Analog Telephone Adapter";
port_re[i]   = "^80$";
url[i]       = "/";
server[i]    = "";
title[i]     = make_list(
                 "Sipura SPA Configuration"
               );
body[i]      = make_list(
                 ">Product Name:<"
               );

i++;
name[i]      = "SonicWALL SSL-VPN Appliance";
url[i]       = "/cgi-bin/welcome/VirtualOffice";
server[i]    = "SonicWALL SSL-VPN Web Server";
body[i]      = make_list(
                 "virtual office - Powered by SonicWALL"
               );

i++;
name[i]      = "AsyncOS";
url[i]       = "/login";
server[i]    = "glass/1.0 Python/2.5.1-IronPort";
title_re[i]  = make_list(
                 "^IronPort [CMX][0-9]+"
               );
body_re[i] = make_list(
                 'alt="IronPort (Spam|[CMX][0-9]+)' 
               ); 

i++;

n = i;

# Check each web server.
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  prev_url = NULL;
  prev_res = NULL;

  for (i=0; i<n; i++)
  {
    # Ignore it if it's supposed to run on a specific set of ports
    # and this port isn't in that list.
    if (
      !isnull(port_re[i]) && 
      !ereg(pattern:port_re[i], string:string(port))
    ) continue;

    # Examine the Server response header.
    banner = get_http_banner(port:port);
    if (isnull(banner)) server_hdr = "";
    else cur_server = egrep(pattern:"^Server:", string:banner);

    if (strlen(cur_server) == 0)
    {
      if (strlen(server[i]) > 0 || strlen(server_re[i]) > 0) continue;
    }
    else
    {
      if (!isnull(server[i]) && server[i] == "") continue;
      if (strlen(server[i]) > 0 && server[i] >!< cur_server) continue;
      if (
        strlen(server_re[i]) > 0 && 
        !ereg(pattern:"^Server: *"+server_re[i]+'[\r\n]*$', string:cur_server)
      ) continue;
    }

    # Fetch the URL if we should test for something in it.
    if (
      isnull(url[i]) && 
      (
        !isnull(title[i]) || !isnull(title_re[i]) || 
        !isnull(body[i]) || !isnull(body_re[i])
      )
    )
    {
      url[i] = "/";
    }
    if (isnull(url[i])) continue;

    if (!isnull(prev_url) && url[i] == prev_url && !isnull(prev_res)) res = prev_res;
    else
    {
      res = http_send_recv3(item:url[i], method:"GET", port:port);
      if (isnull(res) || isnull(res[2])) continue;

      prev_url = url[i];
      prev_res = res;
    }

    # Check the title if appropriate.
    stop_checking = FALSE;
    if (!isnull(title[i]) || !isnull(title_re[i]))
    {
      # Isolate the title.
      cur_title = "";
      title_start = ereg_replace(pattern:'.*(<title>).*', replace:"\1", string:res[2], icase:TRUE);
      if (isnull(title_start)) continue;

      cur_title = strstr(res[2], title_start) - title_start;
      title_end = ereg_replace(pattern:'.*(</title>).*', replace:"\1", string:cur_title, icase:TRUE);
      if (isnull(title_end)) continue;
      cur_title = cur_title - strstr(cur_title, title_end);

      if (!isnull(title[i]))
      {
        foreach t (title[i])
        {
          if (t >!< cur_title)
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
      if (!isnull(title_re[i]))
      {
        foreach t (title_re[i])
        {
          if (egrep(pattern:t, string:cur_title))
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
    }

    # Check the body if appropriate.
    if (!isnull(body[i]) || !isnull(body_re[i]))
    {
      cur_body = res[2];

      if (!isnull(body[i]))
      {
        foreach b (body[i])
        {
          if (b >!< cur_body)
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
      if (!isnull(body_re[i]))
      {
        foreach b (body_re[i])
        {
          if (!egrep(pattern:b, string:cur_body))
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
    }

    # If we get here, we found it.
    set_kb_item(name:"Host/OS/HTML", value:name[i]);
    set_kb_item(name:"Host/OS/HTML/Confidence", value:100);
    set_kb_item(name:"Host/OS/HTML/Type", value:"embedded");

    # Let's make sure the web server is marked as embedded while we're at it.
    replace_or_set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

    exit(0);
  }
}
