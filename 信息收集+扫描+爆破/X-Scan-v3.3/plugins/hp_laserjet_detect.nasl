#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36128);
  script_version("$Revision: 1.3 $");

  script_name(english:"HP LaserJet Detection");
  script_summary(english:"Scrapes model and configuration info from web interface");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a printer." );
  script_set_attribute(attribute:"description", value:
"The remote host is an HP LaserJet Printer." );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (banner) lb = tolower(banner);
else lb = "";
if (
  !lb ||
  (
    "server: hp-chaisoe" >!< lb &&
    "server: hp-chaiserver" >!< lb &&
    "server: virata-emweb" >!< lb
  )
) exit(0);

kb_base = "www/hp_laserjet";
labels["pname"] = "Product Name";
labels["fw"] = "Firmware";
labels["serial"] = "Serial Number";

#Firmware Number labels 

firmware_vals = make_list(
  "Firmware",
  "firmware",
  "Date/code microgl"
);

#Serial Number labels
serial_vals = make_list(
  "Serial Number", 
  "Numero di serie stampante",
  "Produkt-Seriennummer",
  "Numero di serie del produtto",
  "Serienummer for produkt",
  "Produktens serienummer"
);

#Collect various pieces of data.
data = make_array();

res = http_send_recv3(method:"GET", port:port, item:"/hp/device/this.LCDispatcher?nav=hp.config");
if(isnull(res)) exit(0);
else
{
  # - Grab the product model
  if (res[2] =~ '<title>([\\n\\s]+)?(HP|hp) (Color )?LaserJet ([A-Za-z0-9]+)')
  {
    info = strstr(res[2], "<title>");
    if ("</title>" >< info)
    {
      info = chomp(info - strstr(info, "</title>"));
      pat = '(<title>)?(HP|hp) (Color )?LaserJet ([A-Za-z0-9]+)';
      foreach line (split(info, keep:FALSE))
      {
        if (ereg(pattern:pat, string:line))
        {
          matches = eregmatch(pattern:pat, string:line);
          data["pname"] = matches[4];
          break;
        }
      }
    }
  }
  # - Grab the firmware version
  foreach val (firmware_vals)
  {
    if (val >< res[2])
    {
      info = strstr(res[2], val);
      if (ereg(string:info, pattern:string(val, "([\\w\\s]+):</div")))
      {
        info = info - strstr(info, "hpDataItem");
        pat = '([\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?)';
        foreach line (split(info, keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {
            data["fw"] = ereg_replace(pattern:pat, replace:"\1", string:line);
            break;
          }
        }
      }
      else
      {
        info = info - strstr(info, "</tr");
        pat  = '[\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?';
        foreach line (split(info, keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {
            matches = eregmatch(pattern:pat, string:line);
            data["fw"] = matches[0];
            break;
          }
        }
      }
    }
  }

  # - Grab the Serial Number
  foreach val (serial_vals)
  {
    if (val >< res[2])
    {
      info = strstr(res[2], val);
      if (ereg(string:info, pattern:string(val, "[\\w\\s]+:</div")))
      {
        info = info - strstr(info, "hpDataItem");
        pat = '"hpDataItemValue">(\\s+)([\\w\\d]{10})</div>';
        foreach line (split(info, keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {
            matches = eregmatch(pattern:pat, string:line);
            data["serial"] = matches[2];
            break;
          }
        }
      }
      else
      {
        info = info - strstr(info, "</tr");
        if (ereg(string:info, pattern:string(val, ":<")))
          pat = '>([\\w\\d]{10})<';
        else
          pat = string(val, ':[\\s]+([\\w\\d]{10})');

        foreach line (split(info, keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {
            matches = eregmatch(pattern:pat, string:line);
            data["serial"] = matches[1];
            break;
          }
        }
      }
    }
  }
}

# - Check for the Virata-EmWeb server if nothing was found.
if(
  !(data["pname"] ||
    data["fw"] ||
    data["serial"]
  )
)
{  
  res=http_send_recv3(method:"GET", port:port,item:"/info_configuration.html");
  if(isnull(res)) exit(0);
  else
  {
    # - Grab the product model
    if (res[2] =~ '<title>([\\n\\s]+)?(HP|hp) (Color )?LaserJet ([A-Za-z0-9]+)')
    {
      info = strstr(res[2], "<title>");
      if ("</title>" >< info)
      {
        info = info - strstr(info, "</title>");
        pat = '(HP|hp) (Color )?LaserJet ([A-Za-z0-9]+)';
        foreach line (split(info, keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {        
            matches = eregmatch(pattern:pat, string:line);
            data["pname"] = matches[3];
            break;
          }
        }
      }
    }
    # - Grab the firmware version
    foreach val (firmware_vals)
    {
      if (val >< res[2])
      {  
        info = strstr(res[2], val);
        info = info - strstr(info, "</tr");
        pat = '>([\\d]{8}([\\s]+[\\d]+.[\\d]+.[\\d]+)?)<';
        foreach line (split(chomp(info), keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {
            matches = eregmatch(pattern:pat, string:line);
            data["fw"] = matches[1];
            break;
          }
        }
      }
    }
    # - Grab the Serial Number
    foreach val (serial_vals)
    {
      if (val >< res[2])
      {
        info = strstr(res[2], val);
  
        info = info - strstr(info, "</tr");
        pat = '"itemFont">([\\w\\d]{10})<';
        foreach line (split(info, keep:FALSE))
        {
          if (ereg(pattern:pat, string:line))
          {
            matches = eregmatch(pattern:pat, string:line);
            data["serial"] = matches[1];
            break;
          }
        }
      }
    }
  }
  if(
    !(data["pname"] ||
      data["fw"] ||
      data["serial"]
    )
  ) exit(0);
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
foreach key (make_list("pname", "fw", "serial"))
{
  if (val = data[key])
  {
    set_kb_item(name:kb_base+"/"+key, value:val);

    label = labels[key];
    if (key == "pname") val = 'HP LaserJet ' + val;
    info += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
  }
}

if (report_verbosity>0)
{
  report = string(
    "\n",
    info
  );
  security_note(port:port, extra:report);
}
else security_note(port);
