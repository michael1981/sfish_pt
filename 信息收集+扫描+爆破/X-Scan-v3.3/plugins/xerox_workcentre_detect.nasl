#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(18141);
  script_version("$Revision: 1.12 $");

  script_name(english:"XEROX WorkCentre Device Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a printer." );
 script_set_attribute(attribute:"description", value:
"The remote host is a XEROX WorkCentre Device." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
  script_summary(english:"Scrapes model and configuration info from web interface");
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (
  !banner || 
  ("Xerox_MicroServer" >!< banner && "Server: Webserver" >!< banner)
) exit(0);


kb_base = "www/xerox_workcentre";
labels["model"] = "Model";
labels["ssw"]   = "System Software Version";
labels["scd"]   = "Software Compatibility Database Version";
labels["ess"]   = "Net Controller Software Version";


# Collect various pieces of data.
data = make_array();

r = http_send_recv3(method: "GET", item:"/properties/description.dhtml", port:port);
if (isnull(r)) exit(0);
res = r[2];

# - The model number (Properties, Description).
pat = '^[ \t]+(Xerox )?WorkCentre ([^,]+)';
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      data["model"] = item[2];
      break;
    }
  }
}
if (!max_index(keys(data))) exit(0);

# nb: the rest of the info comes from a different page.
r = http_send_recv3(method: "GET", item:"/properties/configuration.dhtml", port:port);
if (isnull(r)) exit(0);
res = r[2];

# - System Software version. 
if ("System Software Version:" >< res)
{
  info = strstr(res, "System Software Version:");
  if ("</tr>" >< info)
  {
    info = info - strstr(info, "</tr>");
    pat = '^[ \t]*([0-9]+[0-9.]+)[ \t]*$';
    foreach line (split(info, keep:FALSE))
    {
      if (match(pattern:pat, string:line))
      {
        data["ssw"] = ereg_replace(pattern:pat, replace:"\1", string:line);
        break;
      }
    }
  }
}

# - Software Compatability Database.
pat = "var versions .+, ([^,]+), Software Compatibility Database";
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      data["scd"] = item[1];
      break;
    }
  }
}

# Examples:
#   'var SysDescrip = "Xerox WorkCentre Pro Multifunction System, ESS 0.R01.02.329.01, IOT 23.16.0, UI 0.2.84.14, Finisher 9.15.0, Scanner 15.7.0;";'
#   'var SysDescrip = "Xerox WorkCentre Pro Multifunction System, ESS 0.S01.02.058.04, IOT 13.0.0, UI 0.1.2.59, Scanner 8.60.0;";'
#   'var SysDescrip = "Xerox WorkCentre Pro Multifunction System; ESS 0.040.022.51031, IOT 50.17.0, UI 0.12.60.54, Finisher 3.20.0, Scanner 4.9.0, BIOS 07.07";'
if ('var SysDescrip = "' >< res)
{
  info = strstr(res, 'var SysDescrip = "') - 'var SysDescrip = "';
  if ('";' >< info)
  {
    info = info - strstr(info, '";');
    if (" ESS " >< info)
    {
      ess = strstr(info, " ESS ") - " ESS ";
      ess = ess - strstr(ess, ", ");
      if (ess =~ "^0\.[RS]") ess = substr(ess, 3);
      else if (ess =~ "^0\.0") ess = substr(ess, 2);

      data["ess"] = ess;
    }
  }
}

# If that didn't work...
if (isnull(ess))
{
  # It may be two lines after the label 'Engine', as occurs with
  # PE120 Series devices.
  i = 0;
  foreach line (split(res, keep:FALSE))
  {
    if (line =~ "^ +Engine:$")
    {
        data["ess"] = lines[i+2];
        break;
    }
    ++i;
  }
}


# Update KB and report findings.
set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
set_kb_item(name:kb_base, value:TRUE);

max_label_len = 0;
foreach key (keys(data))
{
  label = labels[key];
  if (strlen(label) > max_label_len) max_label_len = strlen(label);
}

info = "";
foreach key (make_list("model", "ssw", "sdc", "ess"))
{
  if (val = data[key])
  {
    set_kb_item(name:kb_base+"/"+key, value:val);

    label = labels[key];
    if (key == "model") val = 'Xerox WorkCentre ' + val;
    info += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
  }
}

if (report_verbosity)
{
  report = string(
    "\n",
    info
  );
  security_note(port:port, extra:report);
}
else security_note(port);
