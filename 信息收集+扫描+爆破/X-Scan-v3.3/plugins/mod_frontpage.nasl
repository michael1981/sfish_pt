#
# (C) Tenable Network Security, Inc.
#

# This is the "check" for an old flaw (published in March 2002). We can't
# actually determine the version of the remote mod_frontpage, so we issue
# an alert each time we detect it as running.
#
# Mandrake's Security Advisory states that the flaw is remotely exploitable,
# while FreeBSD's Security advisory (FreeBSD-SA-02:17) claims this is only
# locally exploitable. 
#
# In either case, we can't remotely determine the version of the server, so
# 
# Ref:
# From: FreeBSD Security Advisories <security-advisories@freebsd.org>
# To: FreeBSD Security Advisories <security-advisories@freebsd.org>   
# Subject: FreeBSD Ports Security Advisory FreeBSD-SA-02:17.mod_frontpage
# Message-Id: <200203121428.g2CES9U64467@freefall.freebsd.org>

include("compat.inc");

if(description)
{
 script_id(11303);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0427");
 script_bugtraq_id(4251);
 script_xref(name:"OSVDB", value:"14410"); 
 
 script_name(english:"mod_frontpage for Apache fpexec Remote Overflow");
 script_summary(english:"Checks for the presence of mod_frontpage");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server module has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using the Apache mod_frontpage module.\n\n",
     "mod_frontpage older than 1.6.1 is vulnerable to a buffer\n",
     "overflow which may allow an attacker to gain root access.\n\n",
     "*** Since Nessus was not able to remotely determine the version\n",
     "*** of mod_frontage you are running, you are advised to manually\n",
     "*** check which version you are running as this might be a false\n",
     "*** positive.\n\n",
     "If you want the remote server to be remotely secure, we advise\n",
     "you do not use this module at all."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable this module."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);

if (egrep(pattern:"^Server:.*Apache.*FrontPage.*", string:banner))
{
  security_hole(port);
}
