#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36129);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-4419");
  script_bugtraq_id(33611);
  script_xref(name:"OSVDB", value:"51830");

  script_name(english:"HP LaserJet Web Server Unspecified Admin Component Traversal Arbitrary File Access");
  script_summary(english:"Checks the firmware datecode");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server is an embedded web server for an HP LaserJet
printer. The version of the firmware reported by the printer is
reportedly affected by a directory traversal vulnerability. Because
the printer caches printed files, an attacker could exploit this in
order to gain access to sensitive information." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e066f19" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500986/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500657/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503676/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Upgrade the firmware according to the vendor's advisory.");
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/hp_laserjet/pname", "www/hp_laserjet/fw");

  exit(0);
}

include("global_settings.inc");

printer_model = get_kb_item("www/hp_laserjet/pname");
printer_fw = get_kb_item("www/hp_laserjet/fw");
if (isnull(printer_model) || isnull(printer_fw)) exit(0);

printer_arr = make_array(
                "2410", "20080819",
                "2420", "20080819",
                "2430", "20080819",
                "4250", "20090323",
                "4350", "20090323",
                "5200", "20090305",
                "9040", "20080819",
                "9050", "20080819",
                "4345mfp", "09.120.9",
                "4730mfp", "46.200.9",
                "9040mfp", "08.110.9",
                "9050mfp", "08.110.9",
                "9200C",   "09.120.9",
                "9500mfp", "08.110.9"
              );

# Check the firmware datecode.
info=NULL;

if (printer_arr[printer_model] =~ '[\\d]{8}')
{
  p_fw_ver = ereg_replace(pattern:'([\\d]+)([\\s]+[\\d]+.[\\d]+.[\\d]+)?', replace:"\1", string:printer_fw);
}
else
{
  p_fw_ver = split(ereg_replace(pattern:'([\\d]+)([\\s]+[\\d]+.[\\d]+.[\\d]+)?', replace:"\2", string:printer_fw), sep:".", keep:FALSE);
  fw_ver = split(printer_arr[printer_model], sep:".", keep:FALSE);
}

if ( 
  ( isnull(max_index(p_fw_ver)) && int(p_fw_ver) < int(printer_arr[printer_model])) ||
  max_index(p_fw_ver) &&
  (
    ( int(p_fw_ver[0]) < int(fw_ver[0]) ||
    ( int(p_fw_ver[0]) == int(fw_ver[0]) && int(p_fw_ver[1]) < int(fw_ver[1])) ||
    ( int(p_fw_ver[0]) == int(fw_ver[0]) && int(p_fw_ver[1]) == int(fw_ver[1]) && int(p_fw_ver[2]) < int(fw_ver[2])))
  )
)
{
  if (report_verbosity > 0)
  {
    info = string(
      "\n",
      "The remote LaserJet ", printer_model, "is running firmware version  ", printer_fw, ".\n"
    );
    security_hole(port:0, extra:info);
  }
  else security_hole(port:0);
}
