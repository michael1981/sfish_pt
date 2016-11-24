# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34460);
 script_version("$Revision: 1.9 $");
 script_name(english: "Obsolete Web Server Detection");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is obsolete." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote web server is obsolete and no
longer maintained by its vendor or provider. 

A lack of support implies that no new security patches are being
released for it." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version or switch to another server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 script_summary(english: "Look for old HTTPD banners");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port, ver, dates_re, dates, latest, url, name)
{
  local_var	k, r;

  r = "";
  if (! isnull(dates_re))
  foreach k (keys(dates_re))
    if (ereg(string: ver, pattern: k))
    {
      r = strcat(r, ver, ' support ended');
      if (dates_re[k]) r = strcat(r, ' on ', dates_re[k]);
      r = strcat(r, '.\n');
      break;
    }
  if (! r && ! isnull(dates))
    foreach k (keys(dates))
      if (k >< ver)
      {
        if (name && name >!< k) r = strcat(r, name, " ");
          if (k[strlen(k) - 1] != "/")
            r =  strcat(r, k, ' support ended');
          else
            r =  strcat(r, ver, ' support ended');
         if (dates[k]) r = strcat(r, ' on ', dates[k]);
         r = strcat(r, '.\n');
	  break;
      }
   if (! r) return;
   if (latest) r = strcat(r, 'Upgrade to ', latest, '.\n');
   if (url)  r = strcat(r, '\nSee also : ', url, '\n\n');
   security_hole(port: port, extra: r);
   if (COMMAND_LINE) display(r);
   exit(0);
}


port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
ver = egrep(string: banner, pattern: "^Server:", icase: 1);
if (! ver) exit(0);
ver = ereg_replace(string: chomp(ver), pattern: "^Server: *", replace: "", icase: 1);

v = make_array(
"CERN/3",	"1996-07-15",
"CERN/2",	"1994-05-05",
"CERN/0",	"1993-04-28");
check( port: port, ver: ver, dates: v, 
       url: 'http://www.w3.org/Daemon/Status.html\nhttp://www.w3.org/Daemon/Activity.html');

# Do not add this pattern to the previous array, as hashes are not sorted
check( port: port, ver: ver, dates: make_array("CERN/", "1996-07-15"), 
       url: 'http://www.w3.org/Daemon/Status.html\nhttp://www.w3.org/Daemon/Activity.html');

check( port: port, ver: ver, dates_re: make_array("^NCSA/[1-9]", "1998"),
       latest: 'Apache', url: 'http://hoohoo.ncsa.uiuc.edu/');

check( port: port, ver: ver, 
       dates: make_array("Microsoft-IIS/1.0", ""),
       url: 'http://support.microsoft.com/gp/lifeselectindex#I');

check( port: port, ver: ver,
       dates: make_array("Microsoft-IIS/2.0", "1997-06-30"),
       url: 'http://support.microsoft.com/lifecycle/?p1=2092');

check( port: port, ver: ver, 
       dates: make_array("Microsoft-IIS/3.0", "2000-03-31"),
       url: 'http://support.microsoft.com/lifecycle/?p1=2093');

check( port: port, ver: ver, 
       dates: make_array("Microsoft-IIS/4.0", "2004-12-31"),
       url: 'http://support.microsoft.com/lifecycle/?p1=2094');

# Microsoft-IIS/5.0 extended support will end on 2010-07-13
#  See http://support.microsoft.com/lifecycle/?p1=2095

check( port: port, ver: ver,
       dates_re: make_array( "^Apache/0\.[0-9]", "",
       		 	     "^Apache/1.[0-2]([^0-9].*)?$", ""),
        latest: "Apache/1.3.41", url: "http://httpd.apache.org/" );

check( port: port, ver: ver,
       dates_re: make_array( "^Apache/2.1([^0-9].*)?$", ""),
        latest: "Apache/2.2.10", url: "http://httpd.apache.org/" );

v = make_array(
"Netscape-Enterprise/4.0",	"2002-12-31",
"iPlanet-WebServer-Enterprise/4.0", "2002-12-31",
"iPlanet-WebServer-Enterprise/4.1", "2004-03-31",
"Netscape-Enterprise/3.6",	"2001-01-01 (or earlier)");
check( port: port, ver: ver, dates: v, 
       latest: "Sun Java System Web Server 6.1 or 7.0",
       url: "http://www.sun.com/software/products/web_srvr/lifecycle.xml");

# These servers are very old
v = make_array(
"Netscape-Enterprise/[0-4]\.", "",
"Netscape-Communications/[0-4]\.", "",
"Netscape-Fasttrack/[0-4]\.", "",
"Netscape-Commerce/[0-4]\.", "",
"iPlanet-WebServer-Enterprise/[0-4]\.", ""
);
# iPlanet-Enterprise, Netsite-Commerce, Netsite-Communications

check( port: port, ver: ver, dates_re: v, 
       latest: "Sun Java System Web Server 6.1 or 7.0",
       url: "http://www.sun.com/software/products/web_srvr/lifecycle.xml");

# Sami HTTP Server is not maintained any more
v = make_array("Sami HTTP Server", "");
check( port: port, ver: ver, dates_re: v, 
       url: "http://www.karjasoft.com/old.php");

# Tod Sambar discontinued this web server in 2007
v = make_array("SAMBAR", "2007-12-31");
check( port: port, ver: ver, dates_re: v, 
       url: "http://www.sambarserver.info/viewtopic.php?t=882");
