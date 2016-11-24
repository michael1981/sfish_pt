#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32397);
  script_version("$Revision: 1.6 $");

  script_name(english:"McAfee Common Management Agent Detection");
  script_summary(english:"Checks version of McAfee CMA");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a management agent." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Common Management Agent, a component of
the ePolicy Orchestrator system security management solution from
McAfee." );
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8081);
if (!get_port_state(port)) exit(0);


# Grab the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# If it looks like a CMA.
if ('href="FrameworkLog.xsl"' >< res && "<ePOServerName>" >< res)
{
  # Collect information.
  data = make_array();

  # - version number.
  pat = "<version>([^<]+)</ver";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        data['Agent version'] = ver;
        set_kb_item(name:string("McAfee/CMA/",port,"/Version"), value:ver);

        break;
      }
    }
  }

  # - computer name.
  pat = "<ComputerName>([^<]+)</Computer";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        name = item[1];
        data['Computer name'] = name;
        set_kb_item(name:string("McAfee/CMA/",port,"/Computer_name"), value:name);

        break;
      }
    }
  }

  # Report findings.
  if (report_verbosity > 0 && max_index(keys(data)))
  {
    max_label_len = 0;
    foreach key (keys(data))
    {
      if (strlen(key) > max_label_len) max_label_len = strlen(key);
    }

    info = "";
    foreach key (make_list("Agent version", "Computer name"))
    {
      if (val = data[key])
      {
        info += '  ' + key + crap(data:" ", length:max_label_len-strlen(key)) + ' : ' + val + '\n';
      }
    }

    report = string(
      "\n",
      "Nessus collected the following information from the McAfee Common\n",
      "Management Agent installed on the remote host :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
