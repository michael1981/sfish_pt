#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19194);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2219");
  script_bugtraq_id(14258, 14283);
  script_xref(name:"OSVDB", value:"17899");
  script_xref(name:"OSVDB", value:"17900");
  script_xref(name:"OSVDB", value:"17901");
  script_xref(name:"OSVDB", value:"17902");
  script_xref(name:"OSVDB", value:"17903");
  script_xref(name:"OSVDB", value:"17904");
  script_xref(name:"OSVDB", value:"17905");
  script_xref(name:"OSVDB", value:"17906");
  script_xref(name:"OSVDB", value:"17907");

  name["english"] = "Hosting Controller < 6.1 Hotfix 2.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application with multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Hosting
Controller on the remote host is subject to multiple flaws :

  - Denial of Service Vulnerabilities
    By accessing the 'editplanopt3.asp', 'planmanager.asp',
    and 'plansettings.asp' scripts directly or with specific 
    parameters, an attacker can cause the 'inetinfo.exe' 
    process to consume a large amount of CPU resources.

  - Multiple SQL Injection Vulnerabilities
    An authenticated attacker can affect SQL queries by 
    manipulating input to the 'searchtext' parameter of the
    'IISManagerDB.asp' and 'AccountManager.asp' scripts and
    the 'ListReason' parameter of the 'listreason.asp'
    script.

  - Access Rights Vulnerabilities
    Several scripts fail to restrict access to privileged
    users, which allows non-privileged users to add accounts
    with elevated privileges and make changes to various 
    plan settings. Another failure allows users to gain
    elevated privileges by first accessing the 
    'dsp_newreseller.asp' script before returning to the
    application's homepage." );
 script_set_attribute(attribute:"see_also", value:"http://hostingcontroller.com/english/logs/hotfixlogv61_2_2.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.1 if necessary and apply Hotfix 2.2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Hosting Controller < 6.1 hotfix 2.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("hosting_controller_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/www", 8887);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check for Hosting Controller installs.
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8887);
foreach port (ports) {
  ver = get_kb_item(string("www/", port, "/hosting_controller"));
  if (ver) {
    # nb: versions <= 6.1 hotfix 2.1 are vulnerable.
    if (ver =~ "^(2002|[0-5]\.|6\.(0|1($| hotfix ([01]\.|2\.[0-1]))))") {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      if (!thorough_tests) exit(0);
    }
  }
}
